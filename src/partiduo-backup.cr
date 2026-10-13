# SPDX-License-Identifier: AGPL-3.0-or-later

# Format des sauvegardes de Partiduo (README) : chiffrement (`Crypto`),
# manifeste signé, stockage en écriture unique (`Locator`, `StoreRoot`,
# `StoreServer`) et flux `age` (`Pipe`). Code repris de partiduo-admin.
require "./partiduo-backup/crypto"
require "./partiduo-backup/store"
require "./partiduo-backup/pipe"

module PartiduoBackup
  VERSION = {{
              (read_file("#{__DIR__}/../shard.yml")
                .lines
                .find(&.starts_with?("version:")) || "version: 0.0.0")
                .gsub(/^version:\s*/, "")
                .chomp
            }}
end
