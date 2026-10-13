# SPDX-License-Identifier: AGPL-3.0-or-later

# Format des sauvegardes de Partiduo (README). Le code vient de
# partiduo-admin (`src/shared/backup_crypto.cr`, `src/agent/store.cr`).
module PartiduoBackup
  VERSION = {{
              (read_file("#{__DIR__}/../shard.yml")
                .lines
                .find(&.starts_with?("version:")) || "version: 0.0.0")
                .gsub(/^version:\s*/, "")
                .chomp
            }}
end
