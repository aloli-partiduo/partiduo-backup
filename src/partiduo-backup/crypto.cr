# SPDX-License-Identifier: AGPL-3.0-or-later

require "openssl"
require "json"
require "digest/sha256"
require "random/secure"
require "base64"

# Liaisons de libcrypto (OpenSSL 3) : celles du shard `jose`, déjà présent
# (EVP_PKEY), et, en plus, les clés PEM et RSA-OAEP (clé du cabinet). Préfixe `pd_` :
# aucun conflit avec la bibliothèque standard ni avec `jose`.
require "jose/openssl_ext"

lib LibCrypto
  PD_EVP_PKEY_RSA = 6

  alias PdPemPasswordCallback = (UInt8*, Int32, Int32, Void*) -> Int32

  fun pd_bio_new_mem_buf = BIO_new_mem_buf(buf : Void*, len : Int32) : Bio*
  fun pd_pem_read_bio_pubkey = PEM_read_bio_PUBKEY(bio : Bio*, x : EvpPKey*, cb : PdPemPasswordCallback, u : Void*) : EvpPKey
  fun pd_pem_read_bio_private_key = PEM_read_bio_PrivateKey(bio : Bio*, x : EvpPKey*, cb : PdPemPasswordCallback, u : Void*) : EvpPKey
  fun pd_evp_pkey_get_base_id = EVP_PKEY_get_base_id(pkey : EvpPKey) : Int32
  fun pd_evp_pkey_get_bits = EVP_PKEY_get_bits(pkey : EvpPKey) : Int32
  fun pd_i2d_pubkey = i2d_PUBKEY(pkey : EvpPKey, out : UInt8**) : Int32
  fun pd_evp_pkey_encrypt_init = EVP_PKEY_encrypt_init(ctx : EvpPkeyCtx) : Int32
  fun pd_evp_pkey_encrypt = EVP_PKEY_encrypt(ctx : EvpPkeyCtx, out : UInt8*, outlen : SizeT*, input : UInt8*, inlen : SizeT) : Int32
  fun pd_evp_pkey_decrypt_init = EVP_PKEY_decrypt_init(ctx : EvpPkeyCtx) : Int32
  fun pd_evp_pkey_decrypt = EVP_PKEY_decrypt(ctx : EvpPkeyCtx, out : UInt8*, outlen : SizeT*, input : UInt8*, inlen : SizeT) : Int32
  fun pd_evp_pkey_ctx_ctrl_str = EVP_PKEY_CTX_ctrl_str(ctx : EvpPkeyCtx, type : UInt8*, value : UInt8*) : Int32
  fun pd_err_clear_error = ERR_clear_error
end

module PartiduoBackup
  # Chiffrement des sauvegardes (DECISIONS D-CHF-013 à D-CHF-025 de
  # partiduo-app), partagé par l'exécutant de partiduo-admin (chiffre, relit,
  # signe, vérifie), son administration (clés publiques des cabinets,
  # contrôle d'une clé de sauvegarde, clés de signature des serveurs) et la
  # commande partiduo de partiduo-dist (dossiers locaux, D-LOC-006).
  #
  # * Fichiers au format `age` (C2SP `age-encryption.org/v1`), écrits et lus
  #   par l'outil `age` 1.3 ou suivant (port `security/age`), lancé comme
  #   filtre : aucune primitive de chiffrement du contenu n'est écrite ici.
  # * Une *clé de sauvegarde* par sauvegarde : identité `age` éphémère et
  #   post-quantique (`age-keygen -pq`, `AGE-SECRET-KEY-PQ-1…`) ; ses fichiers
  #   sont chiffrés pour son destinataire (`age1pq1…`).
  # * Une *capsule* garde la clé de sauvegarde : fichier `age` pour les clés
  #   d'exploitation (`….key.age`), ou RSA-OAEP pour la clé du cabinet
  #   (`….key.rsa`). Une rotation ne réécrit que des capsules.
  # * Un *manifeste* texte, signé par la clé Ed25519 du serveur au format
  #   `sshsig` (`ssh-keygen -Y sign -n partiduo-backup`), nomme le serveur,
  #   le dossier, le destinataire et l'empreinte de chaque fichier.
  module Crypto
    # Sauvegarde, clé ou signature illisible, altérée ou refusée.
    class Error < Exception
    end

    EXTENSION    = ".age"
    CAPSULE_AGE  = ".key.age"
    CAPSULE_RSA  = ".key.rsa"
    MANIFEST     = ".manifest"
    SIGNATURE    = ".manifest.sig"
    NAMESPACE    = "partiduo-backup"
    FORMAT       = "partiduo-backup/2"
    MIN_RSA_BITS = 3072
    STANZA       = "mlkem768x25519"

    # Alphabet de bech32 (minuscules) : identités et destinataires `age`.
    BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    # Identité post-quantique (clé de sauvegarde) et son destinataire.
    IDENTITY  = /\AAGE-SECRET-KEY-PQ-1[#{BECH32.upcase}]{20,}\z/
    RECIPIENT = /\Aage1pq1[#{BECH32}]{20,}\z/

    # Modes de chiffrement d'une sauvegarde.
    MODES = %w[none exploitation cabinet]

    def self.valid_identity?(value : String) : Bool
      IDENTITY.matches?(value)
    end

    def self.valid_recipient?(value : String) : Bool
      RECIPIENT.matches?(value)
    end

    def self.sha256(data : String | Bytes) : Bytes
      Digest::SHA256.digest(data)
    end

    # Empreinte présentée à l'écran : chiffres hexadécimaux par groupes de 4.
    def self.display_fingerprint(hex : String) : String
      hex.scan(/.{1,4}/).map(&.[0]).join(' ')
    end

    # Empreinte d'une clé d'exploitation : SHA-256 de son destinataire.
    def self.recipient_fingerprint(recipient : String) : String
      sha256(recipient).hexstring
    end

    # Égalité en temps constant.
    def self.same?(a : Bytes, b : Bytes) : Bool
      return false unless a.size == b.size
      diff = 0_u8
      a.size.times { |index| diff |= a[index] ^ b[index] }
      diff == 0
    end

    # --- Outils -------------------------------------------------------------------

    # Chemin d'un outil : celui des paquets FreeBSD (`/usr/local/bin`), du
    # système de base (`/usr/bin`), sinon celui du PATH. Un démon lancé par
    # rc(8) n'a pas `/usr/local/bin` dans son PATH.
    def self.tool(name : String) : String
      @@tools[name] ||= begin
        ["/usr/local/bin/#{name}", "/usr/bin/#{name}"].find { |path| File::Info.executable?(path) } ||
        Process.find_executable(name) || name
      end
    end

    @@tools = {} of String => String

    # Lance un outil sans shell : rend le code de sortie, la sortie et la
    # sortie d'erreur. `input` : entrée standard (jamais un argument : une
    # clé n'apparaît pas dans la liste des processus).
    def self.run(name : String, args : Array(String), input : String | Bytes? = nil) : {Int32, Bytes, String}
      output = IO::Memory.new
      error = IO::Memory.new
      stdin = input ? IO::Memory.new(input.is_a?(String) ? input.to_slice : input) : Process::Redirect::Close
      status = Process.run(tool(name), args, input: stdin, output: output, error: error)
      {status.exit_code, output.to_slice, error.to_s}
    rescue ex : File::NotFoundError | IO::Error
      raise Error.new("#{name} introuvable ou en échec : #{ex.message}")
    end

    def self.run!(name : String, args : Array(String), input : String | Bytes? = nil) : Bytes
      code, output, errors = run(name, args, input)
      raise Error.new("#{name} (code #{code}) : #{errors.strip.lines.first?}") unless code == 0
      output
    end

    # --- Clés de sauvegarde (D-CHF-014) ------------------------------------------

    record Ephemeral, identity : String, recipient : String

    # Nouvelle clé de sauvegarde, post-quantique : jamais écrite sur le disque
    # par l'outil (sortie standard).
    def self.keygen : Ephemeral
      text = String.new(run!("age-keygen", ["-pq"]))
      identity = text.lines.find(&.starts_with?("AGE-SECRET-KEY-PQ-1")) || raise Error.new("age-keygen : identité absente")
      recipient = recipient_of(identity) || raise Error.new("age-keygen : destinataire illisible")
      Ephemeral.new(identity, recipient)
    end

    # Destinataire d'une identité (`age-keygen -y`) ; `nil` si ce n'est pas
    # une identité post-quantique valide.
    def self.recipient_of(identity : String) : String?
      value = identity.strip
      return unless valid_identity?(value)
      code, output, _ = run("age-keygen", ["-y"], "#{value}\n")
      return unless code == 0
      recipient = String.new(output).strip
      valid_recipient?(recipient) ? recipient : nil
    end

    # Capsule d'exploitation : la clé de sauvegarde chiffrée par `age` pour
    # les clés d'exploitation (post-quantiques seulement : la spécification
    # déconseille de les mêler à d'autres types).
    def self.capsule_for(identity : String, recipients : Array(String)) : Bytes
      raise Error.new("aucune clé d'exploitation") if recipients.empty?
      recipients.each do |recipient|
        raise Error.new("clé d'exploitation refusée (age1pq1… attendue) : #{recipient[0, 20]}…") unless valid_recipient?(recipient)
      end
      run!("age", recipients.flat_map { |recipient| ["-r", recipient] }, "#{identity}\n")
    end

    # Clés d'exploitation d'un fichier : une par ligne, commentaires `#`.
    def self.read_recipients(path : String) : Array(String)
      lines = File.read_lines(path).map(&.strip).reject { |line| line.empty? || line.starts_with?('#') }
      lines.each do |line|
        raise Error.new("#{path} : clé d'exploitation refusée (age1pq1… attendue)") unless valid_recipient?(line)
      end
      raise Error.new("#{path} : aucune clé d'exploitation") if lines.empty?
      lines.uniq
    rescue ex : File::Error
      raise Error.new("clés d'exploitation illisibles : #{ex.message}")
    end

    # Structure d'un fichier `age` sans clé : format v1, post-quantique, un
    # seul destinataire de type `mlkem768x25519` (la clé de sauvegarde).
    # N'authentifie pas le contenu : seule la clé le peut.
    #
    # L'en-tête est lu ici (spécification age-encryption.org/v1 : ligne de
    # version, une strophe `-> type arguments` par destinataire suivie de son
    # corps en base64, ligne `--- mac`), sans `age-inspect` : le port FreeBSD
    # security/age 1.3.2 ne l'installe pas (loulou, 18 octobre 2026).
    # Rend les mêmes champs que `age-inspect --json` (version, postquantum,
    # stanza_types).
    def self.check_structure(path : String) : JSON::Any
      name = File.basename(path)
      info = inspect_header(path)
      unless info["version"]?.try(&.as_s?) == "age-encryption.org/v1"
        raise Error.new("#{name} : ce n'est pas un fichier age")
      end
      unless info["postquantum"]?.try(&.as_s?) == "yes" && info["stanza_types"]?.try(&.as_a?).try(&.map(&.as_s?)) == [STANZA]
        raise Error.new("#{name} : destinataire inattendu (une clé de sauvegarde post-quantique attendue)")
      end
      info
    end

    # Taille maximale lue pour trouver la fin de l'en-tête (`--- `) : un
    # en-tête à un destinataire post-quantique tient en quelques Ko.
    HEADER_LIMIT = 64 * 1024

    def self.inspect_header(path : String) : JSON::Any
      name = File.basename(path)
      types = [] of String
      version = ""
      complete = false
      File.open(path) do |file|
        reader = IO::Sized.new(file, HEADER_LIMIT)
        version = reader.gets(chomp: true) || ""
        while line = reader.gets(chomp: true)
          if line.starts_with?("--- ")
            complete = true
            break
          end
          types << (line.split(' ')[1]? || "") if line.starts_with?("-> ")
        end
      end
      raise Error.new("#{name} : en-tête age incomplet ou trop long") if version == "age-encryption.org/v1" && !complete
      postquantum = !types.empty? && types.all?(STANZA) ? "yes" : "no"
      JSON::Any.new({"version"      => JSON::Any.new(version),
                     "postquantum"  => JSON::Any.new(postquantum),
                     "stanza_types" => JSON::Any.new(types.map { |type| JSON::Any.new(type) })})
    rescue ex : File::Error
      raise Error.new("#{name} : illisible (#{ex.message})")
    end

    # Rappel de mot de passe pour les PEM chiffrés : la phrase de passe est
    # passée par `u` (chaîne terminée par un zéro) ; vide : échec, jamais de
    # question posée sur le terminal.
    PASSWORD_CALLBACK = ->(buffer : UInt8*, size : Int32, _rwflag : Int32, data : Void*) : Int32 {
      return 0 if data.null?
      source = data.as(UInt8*)
      length = LibC.strlen(source).to_i32
      return 0 if length == 0 || length > size
      buffer.copy_from(source, length)
      length
    }

    # Clé publique RSA du cabinet (PEM « PUBLIC KEY », SubjectPublicKeyInfo),
    # 3072 bits au moins. Empreinte : SHA-256 du DER de la clé publique, la
    # même que `openssl pkey -pubin -outform DER | openssl dgst -sha256`.
    class PublicKey
      getter der : Bytes
      getter bits : Int32

      def initialize(pem : String)
        pkey = Crypto.read_pem(pem, secret: false, passphrase: "")
        begin
          unless LibCrypto.pd_evp_pkey_get_base_id(pkey) == LibCrypto::PD_EVP_PKEY_RSA
            raise Error.new("clé publique refusée : RSA seulement")
          end
          @bits = LibCrypto.pd_evp_pkey_get_bits(pkey)
          raise Error.new("clé publique refusée : #{@bits} bits (#{MIN_RSA_BITS} au moins)") if @bits < MIN_RSA_BITS
          @der = Crypto.spki_der(pkey)
          @pem = pem
        ensure
          LibCrypto.evp_pkey_free(pkey)
        end
      end

      def fingerprint : String
        Crypto.sha256(der).hexstring
      end

      def id : Bytes
        Crypto.sha256(der)
      end

      # PEM normalisé (lignes de 64 caractères), tel que conservé.
      def pem : String
        body = Base64.strict_encode(der).scan(/.{1,64}/).map(&.[0]).join('\n')
        "-----BEGIN PUBLIC KEY-----\n#{body}\n-----END PUBLIC KEY-----\n"
      end

      def wrap(secret : Bytes) : Bytes
        pkey = Crypto.read_pem(pem, secret: false, passphrase: "")
        Crypto.rsa_oaep(pkey, secret, encrypt: true)
      ensure
        LibCrypto.evp_pkey_free(pkey) if pkey
      end
    end

    # Clé privée du cabinet (PEM PKCS#8, chiffré ou non). Jamais sur le
    # serveur ni dans l'administration : sert à la commande
    # `partiduo-agent decrypt` sur le poste du cabinet et aux specs.
    class PrivateKey
      @pkey : LibCrypto::EvpPKey?

      def initialize(pem : String, passphrase : String = "")
        pkey = Crypto.read_pem(pem, secret: true, passphrase: passphrase)
        unless LibCrypto.pd_evp_pkey_get_base_id(pkey) == LibCrypto::PD_EVP_PKEY_RSA
          LibCrypto.evp_pkey_free(pkey)
          raise Error.new("clé privée refusée : RSA seulement")
        end
        @pkey = pkey
      end

      def finalize
        @pkey.try { |pkey| LibCrypto.evp_pkey_free(pkey) }
      end

      private def pkey : LibCrypto::EvpPKey
        @pkey || raise Error.new("clé privée fermée")
      end

      def id : Bytes
        Crypto.sha256(Crypto.spki_der(pkey))
      end

      def fingerprint : String
        id.hexstring
      end

      def unwrap(wrapped : Bytes) : Bytes
        Crypto.rsa_oaep(pkey, wrapped, encrypt: false)
      rescue ex : Error
        raise Error.new("mauvaise clé du cabinet : #{ex.message}")
      end
    end

    protected def self.read_pem(pem : String, secret : Bool, passphrase : String) : LibCrypto::EvpPKey
      raise Error.new("clé PEM trop longue") if pem.bytesize > 64 * 1024
      bio = LibCrypto.pd_bio_new_mem_buf(pem.to_unsafe.as(Void*), pem.bytesize)
      raise Error.new("clé PEM illisible") if bio.null?
      begin
        phrase = passphrase.empty? ? Pointer(Void).null : passphrase.to_unsafe.as(Void*)
        pkey = if secret
                 LibCrypto.pd_pem_read_bio_private_key(bio, nil, PASSWORD_CALLBACK, phrase)
               else
                 LibCrypto.pd_pem_read_bio_pubkey(bio, nil, PASSWORD_CALLBACK, phrase)
               end
        if pkey.null?
          LibCrypto.pd_err_clear_error
          raise Error.new(secret ? "clé privée illisible (PEM PKCS#8 attendu ; phrase de passe exacte si elle est chiffrée)" : "clé publique illisible (PEM « PUBLIC KEY » attendu)")
        end
        pkey
      ensure
        LibCrypto.BIO_free(bio)
      end
    end

    protected def self.spki_der(pkey : LibCrypto::EvpPKey) : Bytes
      length = LibCrypto.pd_i2d_pubkey(pkey, nil)
      raise Error.new("clé publique illisible") if length <= 0
      der = Bytes.new(length)
      cursor = der.to_unsafe
      LibCrypto.pd_i2d_pubkey(pkey, pointerof(cursor))
      der
    end

    protected def self.rsa_oaep(pkey : LibCrypto::EvpPKey, input : Bytes, encrypt : Bool) : Bytes
      ctx = LibCrypto.evp_pkey_ctx_new(pkey, nil)
      raise Error.new("RSA-OAEP : contexte") if ctx.null?
      begin
        ok = encrypt ? LibCrypto.pd_evp_pkey_encrypt_init(ctx) : LibCrypto.pd_evp_pkey_decrypt_init(ctx)
        ok = ok == 1 && LibCrypto.pd_evp_pkey_ctx_ctrl_str(ctx, "rsa_padding_mode", "oaep") > 0 &&
             LibCrypto.pd_evp_pkey_ctx_ctrl_str(ctx, "rsa_oaep_md", "sha256") > 0 &&
             LibCrypto.pd_evp_pkey_ctx_ctrl_str(ctx, "rsa_mgf1_md", "sha256") > 0
        raise Error.new("RSA-OAEP : paramètres refusés") unless ok
        length = LibC::SizeT.new(0)
        call = ->(target : UInt8*, size : LibC::SizeT*) {
          encrypt ? LibCrypto.pd_evp_pkey_encrypt(ctx, target, size, input.to_unsafe, input.size) : LibCrypto.pd_evp_pkey_decrypt(ctx, target, size, input.to_unsafe, input.size)
        }
        raise Error.new("RSA-OAEP : taille") unless call.call(Pointer(UInt8).null, pointerof(length)) == 1
        output = Bytes.new(length)
        raise Error.new("RSA-OAEP : #{encrypt ? "chiffrement" : "déchiffrement"} refusé") unless call.call(output.to_unsafe, pointerof(length)) == 1
        output[0, length]
      ensure
        LibCrypto.pd_err_clear_error
        LibCrypto.evp_pkey_ctx_free(ctx)
      end
    end

    # Capsule du cabinet : la clé de sauvegarde (texte) chiffrée par RSA-OAEP
    # pour la clé publique du cabinet ; `openssl pkeyutl -decrypt` l'ouvre.
    def self.capsule_for_cabinet(identity : String, key : PublicKey) : Bytes
      key.wrap(identity.to_slice)
    end

    def self.open_cabinet_capsule(capsule : Bytes, key : PrivateKey) : String
      identity = String.new(key.unwrap(capsule)).strip
      raise Error.new("capsule ouverte, mais sans clé de sauvegarde") unless valid_identity?(identity)
      identity
    end

    # --- Manifeste (D-CHF-018) ----------------------------------------------------

    # Fichier d'une sauvegarde : nom, taille, SHA-256 (tels que conservés).
    record Entry, name : String, size : Int64, sha256 : String

    # Manifeste d'une sauvegarde, texte ligne à ligne, signé par le serveur
    # qui l'a prise. La capsule n'y est pas : elle peut être re-chiffrée
    # (rotation) ; son contenu se contrôle par `recipient`.
    class Manifest
      getter server : String
      getter dossier : String
      getter backup : String
      getter taken_at : Time
      getter mode : String
      getter recipient : String
      getter capsule_keys : Array(String)
      getter cabinet_key : String
      getter files : Array(Entry)

      def initialize(@server : String, @dossier : String, @backup : String, @taken_at : Time, @mode : String,
                     @recipient : String = "", @capsule_keys = [] of String, @cabinet_key : String = "",
                     @files = [] of Entry)
      end

      def to_s(io : IO) : Nil
        io << FORMAT << '\n'
        io << "server " << server << '\n'
        io << "dossier " << dossier << '\n'
        io << "backup " << backup << '\n'
        io << "taken_at " << taken_at.to_utc.to_rfc3339 << '\n'
        io << "mode " << mode << '\n'
        io << "recipient " << recipient << '\n' unless recipient.empty?
        capsule_keys.each { |key| io << "capsule-key " << key << '\n' }
        io << "cabinet-key " << cabinet_key << '\n' unless cabinet_key.empty?
        files.each { |entry| io << "file " << entry.name << ' ' << entry.size << ' ' << entry.sha256 << '\n' }
      end

      def file?(name : String) : Entry?
        files.find { |entry| entry.name == name }
      end

      def sealed? : Bool
        mode != "none"
      end

      SINGLE   = %w[server dossier backup taken_at mode recipient cabinet-key]
      REQUIRED = %w[server dossier backup taken_at mode]

      # Lecture stricte : toute ligne inconnue ou mal formée est refusée.
      def self.parse(text : String) : Manifest
        lines = text.lines
        raise Error.new("manifeste illisible : format inconnu") unless lines.shift? == FORMAT
        values = {} of String => String
        keys = [] of String
        files = [] of Entry
        lines.each do |line|
          name, _, value = line.partition(' ')
          raise Error.new("manifeste illisible : ligne vide") if value.empty?
          if SINGLE.includes?(name)
            raise Error.new("manifeste illisible : #{name} en double") if values.has_key?(name)
            values[name] = value
          elsif name == "capsule-key"
            keys << value
          elsif name == "file"
            files << entry(line, value)
          else
            raise Error.new("manifeste illisible : #{name}")
          end
        end
        build(values, keys, files)
      end

      private def self.entry(line : String, value : String) : Entry
        parts = value.split(' ')
        size = parts[1]?.try(&.to_i64?)
        raise Error.new("manifeste illisible : #{line}") unless parts.size == 3 && size && parts[2].matches?(/\A[0-9a-f]{64}\z/)
        Entry.new(parts[0], size, parts[2])
      end

      private def self.build(values : Hash(String, String), keys : Array(String), files : Array(Entry)) : Manifest
        REQUIRED.each do |required|
          raise Error.new("manifeste illisible : #{required} absent") unless values.has_key?(required)
        end
        mode = values["mode"]
        raise Error.new("manifeste illisible : mode #{mode}") unless MODES.includes?(mode)
        recipient = values["recipient"]? || ""
        unless (mode == "none") == recipient.empty? && (recipient.empty? || Crypto.valid_recipient?(recipient))
          raise Error.new("manifeste illisible : destinataire")
        end
        taken = Time.parse_rfc3339(values["taken_at"]) rescue raise Error.new("manifeste illisible : date")
        new(values["server"], values["dossier"], values["backup"], taken, mode, recipient, keys,
          values["cabinet-key"]? || "", files)
      end
    end

    # --- Signature des serveurs (D-CHF-018) : `sshsig`, Ed25519 ----------------------

    module Signature
      PUBLIC = /\Assh-ed25519 [A-Za-z0-9+\/]+={0,2}\z/

      # Clé publique `ssh-ed25519 AAAA…` (sans commentaire) ; `nil` si ce
      # n'en est pas une.
      def self.normalize(line : String) : String?
        parts = line.strip.split(/\s+/)
        return unless parts.size >= 2
        value = "#{parts[0]} #{parts[1]}"
        return unless PUBLIC.matches?(value)
        Base64.decode(parts[1])
        value
      rescue Base64::Error
        nil
      end

      # Empreinte `SHA256:…`, la même que `ssh-keygen -l`.
      def self.fingerprint(public_line : String) : String
        blob = Base64.decode(public_line.split(' ')[1])
        "SHA256:#{Base64.strict_encode(Crypto.sha256(blob)).rstrip('=')}"
      end

      # Paire Ed25519 sans phrase de passe (hors production : la production
      # reçoit la sienne de beryl).
      def self.generate(path : String, comment : String) : Nil
        Dir.mkdir_p(File.dirname(path), 0o700)
        Crypto.run!("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path])
      end

      def self.public_line(key_path : String) : String
        pub = "#{key_path}.pub"
        text = File.exists?(pub) ? File.read(pub) : String.new(Crypto.run!("ssh-keygen", ["-y", "-f", key_path]))
        normalize(text) || raise Error.new("clé de signature illisible : #{key_path} (Ed25519 attendue)")
      end

      def self.sign(text : String, key_path : String) : String
        String.new(Crypto.run!("ssh-keygen", ["-Y", "sign", "-q", "-f", key_path, "-n", NAMESPACE], text))
      end

      # Ligne `allowed_signers` d'un serveur ; `valid_before` : révocation.
      def self.allowed_signer(principal : String, public_line : String, valid_before : Time? = nil) : String
        options = %(namespaces="#{NAMESPACE}")
        options += %(,valid-before="#{valid_before.to_utc.to_s("%Y%m%d%H%M%SZ")}") if valid_before
        "#{principal} #{options} #{public_line}"
      end

      # Vrai si `signature` est celle de `text` par l'une des clés de
      # `signers` pour `principal`, valable à `at` (date de prise).
      def self.verify(text : String, signature : String, signers : Array(String), principal : String, at : Time? = nil) : Bool
        return false if signers.empty? || signature.empty?
        File.tempfile("partiduo-signers") do |allowed|
          File.tempfile("partiduo-signature") do |sig|
            allowed.print(signers.join('\n') + "\n")
            allowed.flush
            sig.print(signature)
            sig.flush
            args = ["-Y", "verify", "-f", allowed.path, "-I", principal, "-n", NAMESPACE, "-s", sig.path]
            args << "-Overify-time=#{at.to_utc.to_s("%Y%m%d%H%M%SZ")}" if at
            code, _, _ = Crypto.run("ssh-keygen", args, text)
            return code == 0
          ensure
            sig.delete
          end
        ensure
          allowed.delete
        end
        false
      end
    end
  end
end
