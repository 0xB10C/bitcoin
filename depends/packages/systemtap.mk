package=systemtap
$(package)_version=4.6
$(package)_download_path=https://sourceware.org/systemtap/ftp/releases/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=80fb7309232b21349db3db2eea6f1561795225e79c1364c4ada8a66e4412faae

define $(package)_preprocess_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include/sys && \
  cp -r includes/sys $($(package)_staging_prefix_dir)/include
endef
