# SPDX-License-Identifier: AGPL-3.0-or-later

require "./spec_helper"

# Format des sauvegardes (D-CHF-013 à D-CHF-025 de partiduo-app), sans base
# ni réseau : clés de sauvegarde post-quantiques et fichiers `age` en flux,
# capsules, manifeste signé, stockage en écriture unique. Les outils
# officiels (`age`, `age-keygen`, `age-inspect`, `ssh-keygen`, `openssl`)
# servent de seconde implémentation : ce que ce shard écrit, ils le relisent.

private alias Crypto = PartiduoBackup::Crypto

private def scratch(name : String) : String
  path = File.join(Dir.tempdir, "partiduo-chf-#{name}-#{Random::Secure.hex(4)}")
  Dir.mkdir_p(path)
  path
end

# Clé d'exploitation de spec : identité `age` post-quantique en clair dans
# un fichier, et son destinataire.
private def operator(directory : String, name : String = "exploitation") : {String, String}
  path = File.join(directory, "#{name}.age")
  Crypto.run!("age-keygen", ["-pq", "-o", path])
  {path, String.new(Crypto.run!("age-keygen", ["-y", path])).strip}
end

private def manifest(recipient : String = "", mode : String = "none") : Crypto::Manifest
  Crypto::Manifest.new("loulou", "garde", "backup-20261009T101500Z", Time.utc(2026, 10, 9, 10, 15), mode, recipient,
    files: [Crypto::Entry.new("backup-20261009T101500Z.dump.age", 1234_i64, "a" * 64),
            Crypto::Entry.new("backup-20261009T101500Z.media.tar.gz.age", 56_i64, "b" * 64)])
end

describe "Sauvegardes : clés et fichiers age (D-CHF-013, D-CHF-014)" do
  it "tire une clé de sauvegarde post-quantique, dont le destinataire est celui d'age-keygen" do
    key = Crypto.keygen
    Crypto.valid_identity?(key.identity).should be_true
    Crypto.valid_recipient?(key.recipient).should be_true
    key.identity.should start_with("AGE-SECRET-KEY-PQ-1")
    key.recipient.should start_with("age1pq1")
    Crypto.recipient_of(key.identity).should eq(key.recipient)
    Crypto.recipient_of("AGE-SECRET-KEY-1QQQQ").should be_nil
    Crypto.recipient_of("rien").should be_nil
    Crypto.keygen.identity.should_not eq(key.identity)
  end

  it "chiffre un flux pour la clé de sauvegarde (age le relit) et refuse un octet changé ou une autre clé" do
    directory = scratch("flux")
    plain = File.join(directory, "clair.bin")
    data = Random.new(7).random_bytes(300_000)
    File.write(plain, data)
    key = Crypto.keygen
    sealed = File.join(directory, "garde", "backup-20261009T101500Z.dump.age")
    PartiduoBackup::Pipe.seal(sealed, key.recipient) { |io| PartiduoBackup::Pipe.drain(io, ["cat", plain]) }.should eq({0, ""})
    File.read(sealed).starts_with?("age-encryption.org/v1").should be_true
    Dir.children(File.dirname(sealed)).should eq([File.basename(sealed)])
    Crypto.run!("age", ["-d", "-i", "-", sealed], "#{key.identity}\n").should eq(data)
    Crypto.check_structure(sealed)["postquantum"].should eq("yes")
    PartiduoBackup::Pipe.verify(sealed, key.identity)

    # Un programme en échec : rien sous le nom définitif.
    failed = File.join(directory, "garde", "echec.dump.age")
    code, _ = PartiduoBackup::Pipe.seal(failed, key.recipient) { |io| PartiduoBackup::Pipe.drain(io, ["sh", "-c", "exit 3"]) }
    code.should eq(3)
    File.exists?(failed).should be_false
    File.exists?("#{failed}.part").should be_false

    copy = File.join(directory, "copie.bin")
    result, _, age = PartiduoBackup::Pipe.unseal(sealed, key.identity) { |io| PartiduoBackup::Pipe.feed(io, ["dd", "of=#{copy}", "status=none"]) }
    {result[0], age}.should eq({0, 0})
    File.read(copy).to_slice.should eq(data)
    # Un programme qui s'arrête avant la fin du flux (pg_restore --list) ne
    # coupe pas age : tout le fichier est lu et authentifié.
    result, _, age = PartiduoBackup::Pipe.unseal(sealed, key.identity) { |io| PartiduoBackup::Pipe.feed(io, ["head", "-c", "10"]) }
    {result[0], age}.should eq({0, 0})

    expect_raises(Crypto::Error, /authentification refusée/) { PartiduoBackup::Pipe.verify(sealed, Crypto.keygen.identity) }
    File.open(sealed, "r+") do |file|
      file.seek(5000)
      byte = file.read_byte || raise "octet absent"
      file.seek(5000)
      file.write_byte(byte ^ 0x01_u8)
    end
    expect_raises(Crypto::Error, /altérée/) { PartiduoBackup::Pipe.verify(sealed, key.identity) }
    _, _, age = PartiduoBackup::Pipe.unseal(sealed, key.identity) { |io| PartiduoBackup::Pipe.feed(io, ["head", "-c", "10"]) }
    age.should_not eq(0)
  end

  it "refuse comme sauvegarde un fichier age qui n'est pas pour une seule clé de sauvegarde post-quantique" do
    directory = scratch("structure")
    _, recipient = operator(directory)
    classic = String.new(Crypto.run!("age-keygen", [] of String)).lines.find!(&.starts_with?("AGE-SECRET-KEY-1"))
    classic_recipient = String.new(Crypto.run!("age-keygen", ["-y"], classic)).strip
    two = File.join(directory, "deux.age")
    File.write(two, Crypto.run!("age", ["-r", recipient, "-r", Crypto.keygen.recipient], "x"))
    expect_raises(Crypto::Error, /destinataire inattendu/) { Crypto.check_structure(two) }
    old = File.join(directory, "classique.age")
    File.write(old, Crypto.run!("age", ["-r", classic_recipient], "x"))
    expect_raises(Crypto::Error, /destinataire inattendu/) { Crypto.check_structure(old) }
    text = File.join(directory, "texte.age")
    File.write(text, "PDUOBAK ancien format")
    expect_raises(Crypto::Error) { Crypto.check_structure(text) }
  end
end

describe "Sauvegardes : capsules (D-CHF-014, D-CHF-015, D-CHF-020)" do
  it "capsule d'exploitation : chaque détenteur d'une clé d'exploitation l'ouvre avec age, personne d'autre" do
    directory = scratch("capsule")
    first, first_recipient = operator(directory, "premiere")
    second, second_recipient = operator(directory, "seconde")
    stranger, _ = operator(directory, "autre")
    key = Crypto.keygen
    capsule = File.join(directory, "backup.key.age")
    File.write(capsule, Crypto.capsule_for(key.identity, [first_recipient, second_recipient]))
    String.new(Crypto.run!("age", ["-d", "-i", first, capsule])).strip.should eq(key.identity)
    String.new(Crypto.run!("age", ["-d", "-i", second, capsule])).strip.should eq(key.identity)
    expect_raises(Crypto::Error) { Crypto.run!("age", ["-d", "-i", stranger, capsule]) }
    # Rotation : la capsule seule est re-chiffrée, avec les outils standard.
    third, third_recipient = operator(directory, "nouvelle")
    opened = Crypto.run!("age", ["-d", "-i", first, capsule])
    File.write(capsule, Crypto.run!("age", ["-r", third_recipient], opened))
    String.new(Crypto.run!("age", ["-d", "-i", third, capsule])).strip.should eq(key.identity)
    expect_raises(Crypto::Error) { Crypto.run!("age", ["-d", "-i", first, capsule]) }
  end

  it "n'accepte que des clés d'exploitation post-quantiques" do
    directory = scratch("destinataires")
    _, recipient = operator(directory)
    classic = String.new(Crypto.run!("age-keygen", ["-y"], String.new(Crypto.run!("age-keygen", [] of String)))).strip
    expect_raises(Crypto::Error, /age1pq1/) { Crypto.capsule_for(Crypto.keygen.identity, [classic]) }
    expect_raises(Crypto::Error, /aucune/) { Crypto.capsule_for(Crypto.keygen.identity, [] of String) }
    file = File.join(directory, "exploitation.recipients")
    File.write(file, "# clés d'exploitation\n#{recipient}\n\n#{recipient}\n")
    Crypto.read_recipients(file).should eq([recipient])
    File.write(file, "#{classic}\n")
    expect_raises(Crypto::Error, /age1pq1/) { Crypto.read_recipients(file) }
    expect_raises(Crypto::Error, /illisibles/) { Crypto.read_recipients(File.join(directory, "absent")) }
  end

  it "capsule du cabinet : RSA-OAEP, ouverte par openssl pkeyutl ou par la clé privée" do
    pair = BackupSpec::Keys.pair("a")
    key = Crypto.keygen
    capsule = Crypto.capsule_for_cabinet(key.identity, Crypto::PublicKey.new(pair.public_pem))
    path = File.join(scratch("cabinet"), "backup.key.rsa")
    File.write(path, capsule)
    opened = BackupSpec::Keys.openssl(["pkeyutl", "-decrypt", "-inkey", pair.private_path, "-passin", "pass:#{BackupSpec::Keys::PASSPHRASE}",
                                       "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
                                       "-pkeyopt", "rsa_mgf1_md:sha256", "-in", path])
    opened.should eq(key.identity)
    private_key = Crypto::PrivateKey.new(pair.private_pem, BackupSpec::Keys::PASSPHRASE)
    Crypto.open_cabinet_capsule(capsule, private_key).should eq(key.identity)
    other = Crypto::PrivateKey.new(BackupSpec::Keys.pair("b").private_pem, BackupSpec::Keys::PASSPHRASE)
    expect_raises(Crypto::Error) { Crypto.open_cabinet_capsule(capsule, other) }
  end

  it "n'accepte que des clés publiques RSA de 3072 bits au moins, empreinte identique à celle d'openssl" do
    a = BackupSpec::Keys.pair("a")
    key = Crypto::PublicKey.new(a.public_pem)
    key.bits.should eq(3072)
    der = BackupSpec::Keys.openssl(["pkey", "-pubin", "-in", a.public_path, "-outform", "DER"])
    key.fingerprint.should eq(Digest::SHA256.hexdigest(der.to_slice))
    Crypto::PrivateKey.new(a.private_pem, BackupSpec::Keys::PASSPHRASE).fingerprint.should eq(key.fingerprint)
    Crypto.display_fingerprint(key.fingerprint).split(' ').size.should eq(16)
    small = BackupSpec::Keys.pair("petite", 2048)
    expect_raises(Crypto::Error, /2048 bits/) { Crypto::PublicKey.new(small.public_pem) }
    expect_raises(Crypto::Error, /illisible/) { Crypto::PublicKey.new("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n") }
    ec = BackupSpec::Keys.openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
    ec_public = BackupSpec::Keys.openssl(["pkey", "-pubout"], IO::Memory.new(ec))
    expect_raises(Crypto::Error, /RSA seulement/) { Crypto::PublicKey.new(ec_public) }
  end
end

describe "Sauvegardes : manifeste signé (D-CHF-018)" do
  it "écrit un manifeste texte stable et le relit strictement" do
    recipient = Crypto.keygen.recipient
    text = manifest(recipient, "exploitation").to_s
    text.lines.first.should eq("partiduo-backup/2")
    text.should contain("server loulou\n")
    text.should contain("recipient #{recipient}\n")
    text.should contain("file backup-20261009T101500Z.dump.age 1234 #{"a" * 64}\n")
    parsed = Crypto::Manifest.parse(text)
    parsed.to_s.should eq(text)
    parsed.file?("backup-20261009T101500Z.media.tar.gz.age").try(&.size).should eq(56)
    parsed.taken_at.should eq(Time.utc(2026, 10, 9, 10, 15))

    expect_raises(Crypto::Error, /format/) { Crypto::Manifest.parse(text.sub("partiduo-backup/2", "partiduo-backup/1")) }
    expect_raises(Crypto::Error, /commande/) { Crypto::Manifest.parse(text + "commande rm -rf\n") }
    expect_raises(Crypto::Error, /destinataire/) { Crypto::Manifest.parse(text.sub("mode exploitation", "mode none")) }
    expect_raises(Crypto::Error, /en double/) { Crypto::Manifest.parse(text + "server bibou\n") }
    expect_raises(Crypto::Error, /server absent/) { Crypto::Manifest.parse(text.sub("server loulou\n", "")) }
    expect_raises(Crypto::Error) { Crypto::Manifest.parse(text.sub("1234", "beaucoup")) }
    Crypto::Manifest.parse(manifest.to_s).sealed?.should be_false
  end

  it "signe au format sshsig (ssh-keygen vérifie), pour ce serveur, à la date de prise, clé révoquée exclue" do
    directory = scratch("signature")
    key = File.join(directory, "backup-signing.key")
    Crypto::Signature.generate(key, "loulou")
    (File.info(key).permissions.value & 0o077).should eq(0)
    public_line = Crypto::Signature.public_line(key)
    public_line.should start_with("ssh-ed25519 ")
    listed = String.new(Crypto.run!("ssh-keygen", ["-l", "-f", "#{key}.pub"])).split(' ')[1]
    Crypto::Signature.fingerprint(public_line).should eq(listed)

    text = manifest.to_s
    signature = Crypto::Signature.sign(text, key)
    signature.should start_with("-----BEGIN SSH SIGNATURE-----")
    taken = Time.utc(2026, 10, 9, 10, 15)
    signers = [Crypto::Signature.allowed_signer("loulou", public_line)]
    Crypto::Signature.verify(text, signature, signers, "loulou", taken).should be_true
    # Un autre serveur, un texte changé, une signature d'une autre clé.
    Crypto::Signature.verify(text, signature, signers, "bibou", taken).should be_false
    Crypto::Signature.verify(text.sub("1234", "1235"), signature, signers, "loulou", taken).should be_false
    other = File.join(directory, "autre.key")
    Crypto::Signature.generate(other, "bibou")
    Crypto::Signature.verify(text, Crypto::Signature.sign(text, other), signers, "loulou", taken).should be_false
    Crypto::Signature.verify(text, signature, [] of String, "loulou", taken).should be_false
    # Révoquée après la prise : vaut encore ; avant : refusée.
    after = [Crypto::Signature.allowed_signer("loulou", public_line, taken + 1.day)]
    Crypto::Signature.verify(text, signature, after, "loulou", taken).should be_true
    before = [Crypto::Signature.allowed_signer("loulou", public_line, taken - 1.day)]
    Crypto::Signature.verify(text, signature, before, "loulou", taken).should be_false

    Crypto::Signature.normalize("ssh-ed25519 #{public_line.split(' ')[1]} commentaire").should eq(public_line)
    Crypto::Signature.normalize("ssh-rsa AAAAB3NzaC1yc2E").should be_nil
    Crypto::Signature.normalize("ssh-ed25519 pas;du;base64").should be_nil
  end
end

describe "Sauvegardes : stockage en écriture unique (D-CHF-024)" do
  it "n'accepte que des emplacements d'une liste fermée de noms" do
    locator = BackupSpec.locator("loulou/garde/backup-20261009T101500Z.dump.age")
    locator.stem.should eq("backup-20261009T101500Z")
    locator.taken_at.should eq(Time.utc(2026, 10, 9, 10, 15))
    locator.sibling(".manifest.sig").to_s.should eq("loulou/garde/backup-20261009T101500Z.manifest.sig")
    ["loulou/garde/backup-20261009T101500Z.dump.age", "loulou/garde/archive-20161009T101500Z.media.tar.gz",
     "bi.quimeo.net/garde/pre-restore-20261009T101500Z.key.rsa"].each do |value|
      PartiduoBackup::Locator.parse?(value).should_not be_nil
    end
    ["../garde/backup-20261009T101500Z.dump", "loulou/../backup-20261009T101500Z.dump", "loulou/garde/b.dump",
     "loulou/garde/backup-20261009T101500Z.dump.enc", "loulou/admin/backup-20261009T101500Z.dump", "loulou/garde",
     "/var/backups/garde/backup-20261009T101500Z.dump", "lou..lou/garde/backup-20261009T101500Z.dump",
     "loulou/garde/backup-20261009T101500Z.sh"].each do |value|
      PartiduoBackup::Locator.parse?(value).should be_nil
    end
  end

  it "écrit une seule fois, sous le répertoire du serveur client ; lit tout ; garde les archives dans leur durée légale" do
    root = scratch("stockage")
    loulou = PartiduoBackup::StoreRoot.new(root, "loulou")
    bibou = PartiduoBackup::StoreRoot.new(root, "bibou")
    locator = BackupSpec.locator("loulou/garde/backup-20261009T101500Z.dump.age")
    data = Random.new(3).random_bytes(200_000)
    sha = loulou.put(locator, IO::Memory.new(data), data.size.to_i64)
    sha.should eq(Digest::SHA256.hexdigest(data))
    loulou.stat(locator).should eq({data.size.to_i64, sha})
    expect_raises(PartiduoBackup::StoreRoot::Error, /existe déjà/) { loulou.put(locator, IO::Memory.new(data), data.size.to_i64) }
    expect_raises(PartiduoBackup::StoreRoot::Error, /refusée hors de bibou/) { bibou.put(locator.sibling(".manifest"), IO::Memory.new("x"), 1_i64) }
    expect_raises(PartiduoBackup::StoreRoot::Error, /interrompu/) { loulou.put(locator.sibling(".manifest"), IO::Memory.new("x"), 5_i64) }
    loulou.stat(locator.sibling(".manifest")).should be_nil
    Dir.glob(File.join(root, "**", "*.part")).should be_empty

    # Restauration sur un autre serveur : bibou lit ce que loulou a pris.
    copy = IO::Memory.new
    bibou.get(locator, copy)
    copy.to_slice.should eq(data)
    bibou.list("garde").map(&.to_s).should eq([locator.to_s])
    expect_raises(PartiduoBackup::StoreRoot::Error, /refusé hors de bibou/) { bibou.delete(locator) }

    young = BackupSpec.locator("loulou/garde/archive-20250101T000000Z.dump.age")
    old = BackupSpec.locator("loulou/garde/archive-20150101T000000Z.dump.age")
    [young, old].each { |archive| loulou.put(archive, IO::Memory.new("a"), 1_i64) }
    expect_raises(PartiduoBackup::StoreRoot::Error, /durée légale/) { loulou.delete(young, Time.utc(2026, 10, 9)) }
    loulou.delete(old, Time.utc(2026, 10, 9))
    loulou.delete(locator)
    loulou.list("garde").map(&.to_s).should eq([young.to_s])
  end

  it "sert le stockage par le protocole de store-serve : une commande par connexion" do
    root = scratch("protocole")
    data = "contenu chiffré\x00\x01".to_slice
    locator = "loulou/garde/backup-20261009T101500Z.dump.age"
    serve = ->(client : String, input : String | Bytes) do
      output = IO::Memory.new
      code = PartiduoBackup::StoreServer.new(PartiduoBackup::StoreRoot.new(root, client), IO::Memory.new(input), output).serve
      {code, output.to_slice}
    end
    put = IO::Memory.new
    put << "PUT #{locator} #{data.size}\n"
    put.write(data)
    serve.call("loulou", put.to_slice).should eq({0, "OK #{Digest::SHA256.hexdigest(data)}\n".to_slice})
    serve.call("bibou", "GET #{locator}\n").should eq({0, "OK #{data.size}\n".to_slice + data})
    serve.call("bibou", "STAT #{locator}\n").should eq({0, "OK #{data.size} #{Digest::SHA256.hexdigest(data)}\n".to_slice})
    serve.call("bibou", "LIST garde\n").should eq({0, "OK 1\n#{locator}\n".to_slice})
    code, output = serve.call("bibou", "DEL #{locator}\n")
    code.should eq(1)
    String.new(output).should start_with("ERR effacement refusé")
    _, output = serve.call("bibou", "GET loulou/garde/../../etc/passwd\n")
    String.new(output).should start_with("ERR emplacement invalide")
    serve.call("loulou", "STAT loulou/garde/backup-20261009T101500Z.manifest\n").should eq({0, "ERR absent\n".to_slice})
  end
end
