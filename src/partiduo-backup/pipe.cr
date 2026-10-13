# SPDX-License-Identifier: AGPL-3.0-or-later

require "./crypto"

module PartiduoBackup
  # Fichiers `age` en flux : le clair ne passe que par un tube entre un
  # programme (`pg_dump`, `tar`, `pg_restore`…) et `age`, jamais par le
  # disque. Le programme est lancé par l'appelant (bloc), qui garde la main
  # sur la façon de le lancer (enveloppe de sudo, journal).
  module Pipe
    # Écrit dans `path` le flux que `producer` produit sur l'IO reçu,
    # chiffré par `age` pour `recipient`. Fichier partiel renommé à la fin :
    # jamais de sauvegarde incomplète sous son nom définitif. Rend ce que
    # rend `producer` (code de sortie, sortie d'erreur du programme) ; lève
    # `Crypto::Error` si `age` échoue ou si l'écriture est impossible.
    def self.seal(path : String, recipient : String, & : IO -> {Int32, String}) : {Int32, String}
      partial = "#{path}.part"
      begin
        Dir.mkdir_p(File.dirname(path))
        File.write(partial, "", perm: 0o640)
        age_errors = IO::Memory.new
        age = Process.new(Crypto.tool("age"), ["-r", recipient, "-o", partial], input: Process::Redirect::Pipe,
          output: Process::Redirect::Close, error: age_errors)
        result = begin
          yield age.input
        ensure
          age.input.close
        end
        status = age.wait
        unless status.success?
          raise Crypto::Error.new("age (code #{status.exit_code? || -1}) : #{age_errors.to_s.strip[0, 300]?}")
        end
        File.rename(partial, path) if result[0] == 0
        result
      rescue ex : File::Error | IO::Error
        raise Crypto::Error.new("sauvegarde chiffrée non écrite : #{ex.message}")
      ensure
        File.delete(partial) if File.exists?(partial)
      end
    end

    # Déchiffre `path` par `age` (clé de sauvegarde sur son entrée standard :
    # jamais en argument ni sur le disque) et passe le flux à `consumer`.
    # Ce que `consumer` n'a pas lu est lu et jeté : `age` va au bout et
    # authentifie tout le fichier. Rend ce que rend `consumer`, la sortie
    # d'erreur de `age` et son code (0 : fichier authentique).
    def self.unseal(path : String, identity : String, & : IO -> T) : {T, String, Int32} forall T
      age_errors = IO::Memory.new
      age = Process.new(Crypto.tool("age"), ["-d", "-i", "-", path], input: IO::Memory.new("#{identity}\n"),
        output: Process::Redirect::Pipe, error: age_errors)
      begin
        result = yield age.output
        File.open(File::NULL, "w") { |sink| IO.copy(age.output, sink) }
        {result, age_errors.to_s, age.wait.exit_code? || -1}
      ensure
        unless age.terminated?
          age.terminate rescue nil
        end
      end
    rescue ex : File::Error | IO::Error
      raise Crypto::Error.new("sauvegarde chiffrée illisible : #{ex.message}")
    end

    # Programme qui lit `input` sur son entrée standard (sans shell) ; rend
    # son code de sortie et sa sortie d'erreur. S'il s'arrête avant la fin
    # du flux (`pg_restore --list`), le reste est laissé à l'appelant.
    def self.feed(input : IO, argv : Array(String), env = {} of String => String) : {Int32, String}
      errors = IO::Memory.new
      process = begin
        Process.new(argv[0], argv[1..], env: env, input: Process::Redirect::Pipe, output: Process::Redirect::Close, error: errors)
      rescue ex : File::NotFoundError
        raise Crypto::Error.new("#{argv[0]} : #{ex.message}")
      end
      begin
        begin
          IO.copy(input, process.input)
        rescue IO::Error
          # Le programme a fermé son entrée avant la fin du flux.
        end
        begin
          process.input.close
        rescue IO::Error
        end
        {process.wait.exit_code? || -1, errors.to_s}
      ensure
        unless process.terminated?
          process.terminate rescue nil
        end
      end
    end

    # Programme qui écrit sur `output` (sans shell) ; rend son code de sortie
    # et sa sortie d'erreur.
    def self.drain(output : IO, argv : Array(String), env = {} of String => String) : {Int32, String}
      errors = IO::Memory.new
      status = Process.run(argv[0], argv[1..], env: env, input: Process::Redirect::Close, output: output, error: errors)
      {status.exit_code? || -1, errors.to_s}
    rescue ex : File::NotFoundError
      raise Crypto::Error.new("#{argv[0]} : #{ex.message}")
    end

    # Authentifie tout le fichier : `age -d` vers rien. Un octet changé, une
    # troncature ou une mauvaise clé : `Crypto::Error`.
    def self.verify(path : String, identity : String) : Nil
      code, _, errors = Crypto.run("age", ["-d", "-i", "-", "-o", File::NULL, path], "#{identity}\n")
      unless code == 0
        raise Crypto::Error.new("#{File.basename(path)} altérée ou d'une autre clé : authentification refusée " \
                                "(#{errors.strip.lines.first?})")
      end
    end
  end
end
