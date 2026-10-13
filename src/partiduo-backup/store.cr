# SPDX-License-Identifier: AGPL-3.0-or-later

require "digest/sha256"
require "random/secure"

module PartiduoBackup
  # Sous-domaine d'un dossier : même règle que `partiduo-provision` et le
  # protocole de partiduo-admin (`Protocol.valid_slug?`).
  SLUG            = /\A[a-z][a-z0-9-]{0,39}\z/
  RESERVED_SLUGS  = %w[admin www]
  RESERVED_PREFIX = "rt-"
  ARCHIVE_FILE    = /\Aarchive-(\d{8}T\d{6}Z)\./
  # Conservation d'une archive (Code de commerce, art. L123-22) : jamais
  # effacée avant (D-CRA-007 de partiduo-app).
  ARCHIVE_RETENTION_YEARS = 10

  def self.valid_slug?(slug : String) : Bool
    SLUG.matches?(slug) && !slug.ends_with?('-') && !RESERVED_SLUGS.includes?(slug) &&
      !slug.starts_with?(RESERVED_PREFIX)
  end

  # Date de prise d'un fichier d'archive, d'après son nom ; `nil` pour un
  # autre fichier.
  def self.archive_taken_at(path : String) : Time?
    match = ARCHIVE_FILE.match(File.basename(path)) || return
    Time.parse(match[1], "%Y%m%dT%H%M%SZ", Time::Location::UTC)
  rescue Time::Format::Error
    nil
  end

  # Emplacement d'un fichier de sauvegarde dans le stockage (D-CHF-024) :
  # `<serveur>/<sous-domaine>/<fichier>`, le serveur étant celui qui a pris
  # la sauvegarde. Les noms de fichiers forment une liste fermée.
  record Locator, server : String, slug : String, name : String do
    SERVER = /\A[a-z0-9][a-z0-9.-]{0,63}\z/
    NAME   = /\A((?:backup|archive|pre-restore)-(\d{8}T\d{6}Z))\.(dump(\.age)?|media\.tar\.gz(\.age)?|key\.age|key\.rsa|manifest(\.sig)?)\z/

    def self.valid_server?(server : String) : Bool
      SERVER.matches?(server) && !server.includes?("..")
    end

    def self.parse?(value : String) : Locator?
      parts = value.split('/')
      return unless parts.size == 3
      server, slug, name = parts
      return unless valid_server?(server) && PartiduoBackup.valid_slug?(slug) && NAME.matches?(name)
      new(server, slug, name)
    end

    def to_s(io : IO) : Nil
      io << server << '/' << slug << '/' << name
    end

    # `backup-20261009T101500Z` : préfixe commun aux fichiers d'une sauvegarde.
    def stem : String
      NAME.match!(name)[1]
    end

    def taken_at : Time
      Time.parse(NAME.match!(name)[2], "%Y%m%dT%H%M%SZ", Time::Location::UTC)
    end

    def sibling(suffix : String) : Locator
      Locator.new(server, slug, "#{stem}#{suffix}")
    end
  end

  # Racine du stockage, côté serveur de sauvegarde. `client` : le serveur
  # qui s'y connecte ; il n'écrit et n'efface que sous `<client>/`, lit tout
  # (restauration sur un autre serveur, D-CHF-016). Une archive dans sa
  # durée légale n'est jamais effacée (D-CRA-007), quel que soit le client.
  class StoreRoot
    class Error < Exception
    end

    getter root : String
    getter client : String

    def initialize(@root : String, @client : String)
      raise Error.new("serveur client invalide : #{@client}") unless Locator.valid_server?(@client)
    end

    def path(locator : Locator) : String
      File.join(root, locator.server, locator.slug, locator.name)
    end

    def put(locator : Locator, input : IO, size : Int64) : String
      raise Error.new("écriture refusée hors de #{client}/ : #{locator}") unless locator.server == client
      target = path(locator)
      raise Error.new("existe déjà : #{locator}") if File.exists?(target)
      Dir.mkdir_p(File.dirname(target), 0o750)
      partial = "#{target}.#{Random::Secure.hex(6)}.part"
      digest = Digest::SHA256.new
      begin
        File.open(partial, "wb", perm: 0o640) do |file|
          buffer = Bytes.new(65_536)
          remaining = size
          while remaining > 0
            count = input.read(buffer[0, Math.min(buffer.size.to_i64, remaining).to_i32])
            raise Error.new("envoi interrompu : #{locator}") if count == 0
            file.write(buffer[0, count])
            digest.update(buffer[0, count])
            remaining -= count
          end
          file.fsync
        end
        # Lien physique : échoue si le fichier est apparu entre-temps.
        File.link(partial, target)
      rescue File::AlreadyExistsError
        raise Error.new("existe déjà : #{locator}")
      ensure
        File.delete(partial) if File.exists?(partial)
      end
      digest.hexfinal
    end

    def size(locator : Locator) : Int64?
      target = path(locator)
      File.file?(target) ? File.size(target).to_i64 : nil
    end

    def get(locator : Locator, output : IO) : Nil
      File.open(path(locator), "rb") { |file| IO.copy(file, output) }
    rescue File::Error
      raise Error.new("absent : #{locator}")
    end

    def stat(locator : Locator) : {Int64, String}?
      target = path(locator)
      return unless File.file?(target)
      {File.size(target).to_i64, Digest::SHA256.new.file(target).hexfinal}
    end

    def list(slug : String) : Array(Locator)
      raise Error.new("sous-domaine invalide : #{slug}") unless PartiduoBackup.valid_slug?(slug)
      Dir.glob(File.join(root, "*", slug, "*")).compact_map do |file|
        Locator.parse?(file.lchop(root).lchop('/'))
      end.sort_by!(&.to_s)
    end

    def delete(locator : Locator, now : Time = Time.utc) : Nil
      raise Error.new("effacement refusé hors de #{client}/ : #{locator}") unless locator.server == client
      if taken = PartiduoBackup.archive_taken_at(locator.name)
        if taken.shift(years: ARCHIVE_RETENTION_YEARS) > now
          raise Error.new("archive dans sa durée légale de conservation : #{locator.name}")
        end
      end
      target = path(locator)
      File.delete(target) if File.exists?(target)
    end
  end

  # `partiduo-agent store-serve` : une commande par connexion, sur l'entrée
  # et la sortie standard (commande forcée de `authorized_keys`).
  #
  # * `PUT <emplacement> <taille>` puis les octets → `OK <sha256>`
  # * `GET <emplacement>` → `OK <taille>` puis les octets
  # * `STAT <emplacement>` → `OK <taille> <sha256>` ou `ERR absent`
  # * `LIST <sous-domaine>` → `OK <n>` puis n emplacements
  # * `DEL <emplacement>` → `OK`
  #
  # Toute erreur : `ERR <motif>`.
  class StoreServer
    def initialize(@root : StoreRoot, @input : IO, @output : IO)
    end

    def serve : Int32
      line = @input.gets(chomp: true) || return 0
      verb, _, rest = line.partition(' ')
      case verb
      when "PUT"
        target, _, size = rest.partition(' ')
        bytes = size.to_i64? || raise StoreRoot::Error.new("taille invalide")
        reply("OK #{@root.put(locator!(target), @input, bytes)}")
      when "GET"
        locator = locator!(rest)
        size = @root.size(locator) || raise StoreRoot::Error.new("absent : #{locator}")
        reply("OK #{size}")
        @root.get(locator, @output)
      when "STAT"
        if found = @root.stat(locator!(rest))
          reply("OK #{found[0]} #{found[1]}")
        else
          reply("ERR absent")
        end
      when "LIST"
        found = @root.list(rest)
        reply("OK #{found.size}")
        found.each { |locator| @output << locator << '\n' }
      when "DEL"
        @root.delete(locator!(rest))
        reply("OK")
      else
        raise StoreRoot::Error.new("commande inconnue")
      end
      @output.flush
      0
    rescue ex : StoreRoot::Error | IO::Error
      reply("ERR #{ex.message.to_s.gsub('\n', ' ')}")
      @output.flush rescue nil
      1
    end

    private def locator!(value : String) : Locator
      Locator.parse?(value) || raise StoreRoot::Error.new("emplacement invalide : #{value}")
    end

    private def reply(line : String) : Nil
      @output << line << '\n'
    end
  end
end
