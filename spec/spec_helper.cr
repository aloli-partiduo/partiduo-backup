# SPDX-License-Identifier: AGPL-3.0-or-later

require "spec"
require "../src/partiduo-backup"

module BackupSpec
  # Paires de clés RSA de cabinet, produites par la commande locale
  # documentée (`openssl genpkey`), une fois par exécution.
  module Keys
    PASSPHRASE = "phrase de passe du cabinet"

    record Pair, private_pem : String, public_pem : String, directory : String do
      def private_path : String
        File.join(directory, "cabinet-prive.pem")
      end

      def public_path : String
        File.join(directory, "cabinet-public.pem")
      end
    end

    @@pairs = {} of String => Pair

    def self.pair(name : String = "a", bits : Int32 = 3072) : Pair
      @@pairs["#{name}-#{bits}"] ||= generate(name, bits)
    end

    private def self.generate(name : String, bits : Int32) : Pair
      directory = File.join(Dir.tempdir, "partiduo-backup-keys-#{name}-#{bits}-#{Random::Secure.hex(4)}")
      Dir.mkdir_p(directory)
      private_path = File.join(directory, "cabinet-prive.pem")
      public_path = File.join(directory, "cabinet-public.pem")
      openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:#{bits}", "-aes-256-cbc",
               "-pass", "pass:#{PASSPHRASE}", "-out", private_path])
      openssl(["pkey", "-in", private_path, "-passin", "pass:#{PASSPHRASE}", "-pubout", "-out", public_path])
      Pair.new(File.read(private_path), File.read(public_path), directory)
    end

    def self.openssl(args : Array(String), input : Process::Stdio = Process::Redirect::Close) : String
      output = IO::Memory.new
      error = IO::Memory.new
      status = Process.run("openssl", args, input: input, output: output, error: error)
      raise "openssl #{args.first} : #{error}" unless status.success?
      output.to_s
    end
  end

  def self.locator(value : String) : PartiduoBackup::Locator
    PartiduoBackup::Locator.parse?(value) || raise "emplacement refusé : #{value}"
  end
end
