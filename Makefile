
# This makefile was generated using 'configure.py --cc=msvc --cpu=i386'

# Paths to relevant programs

CXX            = cl
LINKER         = link
AR             = lib
AR_OPTIONS     = /nologo
PYTHON_EXE     = C:\Users\dwfen\AppData\Local\Programs\Python\Python39\python.exe

# Compiler Flags

ABI_FLAGS      =  
LANG_FLAGS     = /EHs /GR /D_WIN32_WINNT=0x0600
CXXFLAGS       = /MD /bigobj /O2 /Oi -DBOTAN_IS_BEING_BUILT
WARN_FLAGS     = /W4 /wd4250 /wd4251 /wd4275 /wd4127
LIB_FLAGS      =  /DBOTAN_DLL=__declspec(dllexport)
LDFLAGS        = 

EXE_LINK_CMD   = $(LINKER)

LIB_LINKS_TO   =  crypt32.lib user32.lib ws2_32.lib
EXE_LINKS_TO   = .\botan.lib $(LIB_LINKS_TO) 

BUILD_FLAGS    = $(ABI_FLAGS) $(LANG_FLAGS) $(CXXFLAGS) $(WARN_FLAGS)

SCRIPTS_DIR    = src/scripts
INSTALLED_LIB_DIR = c:\Botan\lib

# The primary target
all: libs cli tests docs

# Executable targets
CLI           = .\botan-cli.exe
TEST          = .\botan-test.exe
LIBRARIES     = .\botan.dll

cli: $(CLI)
tests: $(TEST)
libs: $(LIBRARIES)
docs: build\doc.stamp

# Misc targets


build\doc.stamp: doc/*.rst doc/api_ref/*.rst doc/dev_ref/*.rst
	"$(PYTHON_EXE)" "$(SCRIPTS_DIR)/build_docs.py" --build-dir="build"

clean:
	"$(PYTHON_EXE)" "$(SCRIPTS_DIR)/cleanup.py" --build-dir="build"

distclean:
	"$(PYTHON_EXE)" "$(SCRIPTS_DIR)/cleanup.py" --build-dir="build" --distclean

install: libs cli docs
	"$(PYTHON_EXE)" "$(SCRIPTS_DIR)/install.py" --prefix="c:\Botan" --build-dir="build" --bindir="c:\Botan\bin" --libdir="c:\Botan\lib" --docdir="docs" --includedir="include"

check: tests
	"$(PYTHON_EXE)" "$(SCRIPTS_DIR)/check.py" --build-dir="build"

# Object Files
LIBOBJS = build\obj\lib\asn1_alg_id.obj build\obj\lib\asn1_obj.obj build\obj\lib\asn1_oid.obj build\obj\lib\asn1_print.obj build\obj\lib\asn1_str.obj build\obj\lib\asn1_time.obj build\obj\lib\asn1_ber_dec.obj build\obj\lib\asn1_der_enc.obj build\obj\lib\asn1_oid_maps.obj build\obj\lib\asn1_oids.obj build\obj\lib\base_buf_comp.obj build\obj\lib\base_scan_name.obj build\obj\lib\base_sym_algo.obj build\obj\lib\base_symkey.obj build\obj\lib\block_aes.obj build\obj\lib\block_aes_ni.obj build\obj\lib\block_aria.obj build\obj\lib\block_cipher.obj build\obj\lib\block_blowfish.obj build\obj\lib\block_camellia.obj build\obj\lib\block_cascade.obj build\obj\lib\block_cast128.obj build\obj\lib\block_cast256.obj build\obj\lib\block_des.obj build\obj\lib\block_des_tab.obj build\obj\lib\block_des_desx.obj build\obj\lib\block_gost_28147.obj build\obj\lib\block_idea.obj build\obj\lib\block_idea_sse2.obj build\obj\lib\block_kasumi.obj build\obj\lib\block_lion.obj build\obj\lib\block_misty1.obj build\obj\lib\block_noekeon.obj build\obj\lib\block_noekeon_simd.obj build\obj\lib\block_seed.obj build\obj\lib\block_serpent.obj build\obj\lib\block_serpent_simd.obj build\obj\lib\block_shacal2.obj build\obj\lib\block_shacal2_simd.obj build\obj\lib\block_shacal2_x86.obj build\obj\lib\block_sm4.obj build\obj\lib\block_threefish_512.obj build\obj\lib\block_twofish.obj build\obj\lib\block_twofish_tab.obj build\obj\lib\block_xtea.obj build\obj\lib\codec_base32.obj build\obj\lib\codec_base58.obj build\obj\lib\codec_base64.obj build\obj\lib\codec_hex.obj build\obj\lib\compat_sodium_25519.obj build\obj\lib\compat_sodium_aead.obj build\obj\lib\compat_sodium_auth.obj build\obj\lib\compat_sodium_box.obj build\obj\lib\compat_sodium_chacha.obj build\obj\lib\compat_sodium_salsa.obj build\obj\lib\compat_sodium_secretbox.obj build\obj\lib\compat_sodium_utils.obj build\obj\lib\entropy_srcs.obj build\obj\lib\entropy_rdseed.obj build\obj\lib\entropy_win32_stats_es_win32.obj build\obj\lib\ffi.obj build\obj\lib\ffi_block.obj build\obj\lib\ffi_cert.obj build\obj\lib\ffi_cipher.obj build\obj\lib\ffi_fpe.obj build\obj\lib\ffi_hash.obj build\obj\lib\ffi_hotp.obj build\obj\lib\ffi_kdf.obj build\obj\lib\ffi_keywrap.obj build\obj\lib\ffi_mac.obj build\obj\lib\ffi_mp.obj build\obj\lib\ffi_pk_op.obj build\obj\lib\ffi_pkey.obj build\obj\lib\ffi_pkey_algs.obj build\obj\lib\ffi_rng.obj build\obj\lib\ffi_totp.obj build\obj\lib\filters_algo_filt.obj build\obj\lib\filters_b64_filt.obj build\obj\lib\filters_basefilt.obj build\obj\lib\filters_buf_filt.obj build\obj\lib\filters_cipher_filter.obj build\obj\lib\filters_comp_filter.obj build\obj\lib\filters_data_snk.obj build\obj\lib\filters_filter.obj build\obj\lib\filters_hex_filt.obj build\obj\lib\filters_out_buf.obj build\obj\lib\filters_pipe.obj build\obj\lib\filters_pipe_io.obj build\obj\lib\filters_pipe_rw.obj build\obj\lib\filters_secqueue.obj build\obj\lib\filters_threaded_fork.obj build\obj\lib\hash_blake2_blake2b.obj build\obj\lib\hash_checksum_adler32.obj build\obj\lib\hash_checksum_crc24.obj build\obj\lib\hash_checksum_crc32.obj build\obj\lib\hash_comb4p.obj build\obj\lib\hash_gost_3411.obj build\obj\lib\hash.obj build\obj\lib\hash_keccak.obj build\obj\lib\hash_md4.obj build\obj\lib\hash_md5.obj build\obj\lib\hash_mdx_hash.obj build\obj\lib\hash_par_hash.obj build\obj\lib\hash_rmd160.obj build\obj\lib\hash_sha1_sha160.obj build\obj\lib\hash_sha1_sse2.obj build\obj\lib\hash_sha1_x86.obj build\obj\lib\hash_sha2_32.obj build\obj\lib\hash_sha2_32_sha2_32_x86.obj build\obj\lib\hash_sha2_64.obj build\obj\lib\hash_sha3.obj build\obj\lib\hash_shake.obj build\obj\lib\hash_skein_512.obj build\obj\lib\hash_sm3.obj build\obj\lib\hash_streebog.obj build\obj\lib\hash_streebog_precalc.obj build\obj\lib\hash_tiger_tig_tab.obj build\obj\lib\hash_tiger.obj build\obj\lib\hash_whirlpool.obj build\obj\lib\hash_whirlpool_whrl_tab.obj build\obj\lib\kdf_hkdf.obj build\obj\lib\kdf.obj build\obj\lib\kdf_kdf1.obj build\obj\lib\kdf_kdf1_iso18033.obj build\obj\lib\kdf_kdf2.obj build\obj\lib\kdf_prf_tls.obj build\obj\lib\kdf_prf_x942.obj build\obj\lib\kdf_sp800_108.obj build\obj\lib\kdf_sp800_56a.obj build\obj\lib\kdf_sp800_56c.obj build\obj\lib\mac_cbc_mac.obj build\obj\lib\mac_cmac.obj build\obj\lib\mac_gmac.obj build\obj\lib\mac_hmac.obj build\obj\lib\mac.obj build\obj\lib\mac_poly1305.obj build\obj\lib\mac_siphash.obj build\obj\lib\mac_x919_mac.obj build\obj\lib\math_bigint_big_code.obj build\obj\lib\math_bigint_big_io.obj build\obj\lib\math_bigint_big_ops2.obj build\obj\lib\math_bigint_big_ops3.obj build\obj\lib\math_bigint_big_rand.obj build\obj\lib\math_bigint.obj build\obj\lib\math_bigint_divide.obj build\obj\lib\math_mp_comba.obj build\obj\lib\math_mp_karat.obj build\obj\lib\math_mp_monty.obj build\obj\lib\math_mp_monty_n.obj build\obj\lib\math_numbertheory_dsa_gen.obj build\obj\lib\math_numbertheory_jacobi.obj build\obj\lib\math_numbertheory_make_prm.obj build\obj\lib\math_numbertheory_mod_inv.obj build\obj\lib\math_numbertheory_monty.obj build\obj\lib\math_numbertheory_monty_exp.obj build\obj\lib\math_numbertheory_mp_numth.obj build\obj\lib\math_numbertheory_nistp_redc.obj build\obj\lib\math_numbertheory_numthry.obj build\obj\lib\math_numbertheory_pow_mod.obj build\obj\lib\math_numbertheory_primality.obj build\obj\lib\math_numbertheory_primes.obj build\obj\lib\math_numbertheory_reducer.obj build\obj\lib\math_numbertheory_ressol.obj build\obj\lib\misc_aont_package.obj build\obj\lib\misc_cryptobox.obj build\obj\lib\misc_fpe_fe1.obj build\obj\lib\misc_hotp.obj build\obj\lib\misc_hotp_totp.obj build\obj\lib\misc_nist_keywrap.obj build\obj\lib\misc_rfc3394.obj build\obj\lib\misc_roughtime.obj build\obj\lib\misc_srp6.obj build\obj\lib\misc_tss.obj build\obj\lib\modes_aead.obj build\obj\lib\modes_aead_ccm.obj build\obj\lib\modes_aead_chacha20poly1305.obj build\obj\lib\modes_aead_eax.obj build\obj\lib\modes_aead_gcm.obj build\obj\lib\modes_aead_ocb.obj build\obj\lib\modes_aead_siv.obj build\obj\lib\modes_cbc.obj build\obj\lib\modes_cfb.obj build\obj\lib\modes_cipher_mode.obj build\obj\lib\modes_mode_pad.obj build\obj\lib\modes_xts.obj build\obj\lib\passhash_bcrypt.obj build\obj\lib\passhash_passhash9.obj build\obj\lib\pbkdf_argon2.obj build\obj\lib\pbkdf_argon2_argon2fmt.obj build\obj\lib\pbkdf_argon2_argon2pwhash.obj build\obj\lib\pbkdf_bcrypt_pbkdf.obj build\obj\lib\pbkdf.obj build\obj\lib\pbkdf_pbkdf1.obj build\obj\lib\pbkdf_pbkdf2.obj build\obj\lib\pbkdf_pgp_s2k.obj build\obj\lib\pbkdf_pwdhash.obj build\obj\lib\pbkdf_scrypt.obj build\obj\lib\pk_pad_eme.obj build\obj\lib\pk_pad_eme_oaep_oaep.obj build\obj\lib\pk_pad_eme_pkcs1_eme_pkcs.obj build\obj\lib\pk_pad_eme_raw.obj build\obj\lib\pk_pad_emsa.obj build\obj\lib\pk_pad_emsa1.obj build\obj\lib\pk_pad_emsa_pkcs1.obj build\obj\lib\pk_pad_emsa_pssr_pssr.obj build\obj\lib\pk_pad_emsa_raw.obj build\obj\lib\pk_pad_emsa_x931.obj build\obj\lib\pk_pad_hash_id.obj build\obj\lib\pk_pad_iso9796.obj build\obj\lib\pk_pad_mgf1.obj build\obj\lib\pk_pad_padding.obj build\obj\lib\prov_pkcs11_p11.obj build\obj\lib\prov_pkcs11_p11_ecc_key.obj build\obj\lib\prov_pkcs11_p11_ecdh.obj build\obj\lib\prov_pkcs11_p11_ecdsa.obj build\obj\lib\prov_pkcs11_p11_mechanism.obj build\obj\lib\prov_pkcs11_p11_module.obj build\obj\lib\prov_pkcs11_p11_object.obj build\obj\lib\prov_pkcs11_p11_randomgenerator.obj build\obj\lib\prov_pkcs11_p11_rsa.obj build\obj\lib\prov_pkcs11_p11_session.obj build\obj\lib\prov_pkcs11_p11_slot.obj build\obj\lib\prov_pkcs11_p11_x509.obj build\obj\lib\psk_db.obj build\obj\lib\psk_db_psk_db_sql.obj build\obj\lib\pubkey_blinding.obj build\obj\lib\pubkey_cecpq1.obj build\obj\lib\pubkey_curve25519.obj build\obj\lib\pubkey_curve25519_donna.obj build\obj\lib\pubkey_dh.obj build\obj\lib\pubkey_dl_algo.obj build\obj\lib\pubkey_dl_group.obj build\obj\lib\pubkey_dl_group_dl_named.obj build\obj\lib\pubkey_dlies.obj build\obj\lib\pubkey_dsa.obj build\obj\lib\pubkey_ec_group_curve_gfp.obj build\obj\lib\pubkey_ec_group.obj build\obj\lib\pubkey_ec_group_ec_named.obj build\obj\lib\pubkey_ec_group_point_gfp.obj build\obj\lib\pubkey_ec_group_point_mul.obj build\obj\lib\pubkey_ecc_key.obj build\obj\lib\pubkey_ecdh.obj build\obj\lib\pubkey_ecdsa.obj build\obj\lib\pubkey_ecgdsa.obj build\obj\lib\pubkey_ecies.obj build\obj\lib\pubkey_eckcdsa.obj build\obj\lib\pubkey_ed25519.obj build\obj\lib\pubkey_ed25519_fe.obj build\obj\lib\pubkey_ed25519_key.obj build\obj\lib\pubkey_ed25519_ge.obj build\obj\lib\pubkey_ed25519_sc_muladd.obj build\obj\lib\pubkey_ed25519_sc_reduce.obj build\obj\lib\pubkey_elgamal.obj build\obj\lib\pubkey_gost_3410.obj build\obj\lib\pubkey_keypair.obj build\obj\lib\pubkey_mce_code_based_key_gen.obj build\obj\lib\pubkey_mce_gf2m_rootfind_dcmp.obj build\obj\lib\pubkey_mce_gf2m_small_m.obj build\obj\lib\pubkey_mce_goppa_code.obj build\obj\lib\pubkey_mce_workfactor.obj build\obj\lib\pubkey_mce_mceliece.obj build\obj\lib\pubkey_mce_mceliece_key.obj build\obj\lib\pubkey_mce_polyn_gf2m.obj build\obj\lib\pubkey_mceies.obj build\obj\lib\pubkey_newhope.obj build\obj\lib\pubkey_pbes2.obj build\obj\lib\pubkey_pem.obj build\obj\lib\pubkey_pk_algs.obj build\obj\lib\pubkey_pk_keys.obj build\obj\lib\pubkey_pk_ops.obj build\obj\lib\pubkey_pkcs8.obj build\obj\lib\pubkey.obj build\obj\lib\pubkey_rfc6979.obj build\obj\lib\pubkey_rsa.obj build\obj\lib\pubkey_sm2.obj build\obj\lib\pubkey_sm2_enc.obj build\obj\lib\pubkey_workfactor.obj build\obj\lib\pubkey_x509_key.obj build\obj\lib\pubkey_xmss_common_ops.obj build\obj\lib\pubkey_xmss_hash.obj build\obj\lib\pubkey_xmss_index_registry.obj build\obj\lib\pubkey_xmss_parameters.obj build\obj\lib\pubkey_xmss_privatekey.obj build\obj\lib\pubkey_xmss_publickey.obj build\obj\lib\pubkey_xmss_signature.obj build\obj\lib\pubkey_xmss_signature_operation.obj build\obj\lib\pubkey_xmss_verification_operation.obj build\obj\lib\pubkey_xmss_wots_parameters.obj build\obj\lib\pubkey_xmss_wots_privatekey.obj build\obj\lib\pubkey_xmss_wots_publickey.obj build\obj\lib\rng_auto_rng.obj build\obj\lib\rng_chacha_rng.obj build\obj\lib\rng_hmac_drbg.obj build\obj\lib\rng_processor_rng.obj build\obj\lib\rng_rdrand_rng.obj build\obj\lib\rng.obj build\obj\lib\rng_stateful_rng.obj build\obj\lib\rng_system_rng.obj build\obj\lib\stream_chacha.obj build\obj\lib\stream_chacha_simd32.obj build\obj\lib\stream_ctr.obj build\obj\lib\stream_ofb.obj build\obj\lib\stream_rc4.obj build\obj\lib\stream_salsa20.obj build\obj\lib\stream_shake_cipher.obj build\obj\lib\stream_cipher.obj build\obj\lib\tls_credentials_manager.obj build\obj\lib\tls_msg_cert_req.obj build\obj\lib\tls_msg_cert_status.obj build\obj\lib\tls_msg_cert_verify.obj build\obj\lib\tls_msg_certificate.obj build\obj\lib\tls_msg_client_hello.obj build\obj\lib\tls_msg_client_kex.obj build\obj\lib\tls_msg_finished.obj build\obj\lib\tls_msg_hello_verify.obj build\obj\lib\tls_msg_server_hello.obj build\obj\lib\tls_msg_server_kex.obj build\obj\lib\tls_msg_session_ticket.obj build\obj\lib\tls_sessions_sql_tls_session_manager_sql.obj build\obj\lib\tls_alert.obj build\obj\lib\tls_algos.obj build\obj\lib\tls_blocking.obj build\obj\lib\tls_callbacks.obj build\obj\lib\tls_cbc.obj build\obj\lib\tls_channel.obj build\obj\lib\tls_ciphersuite.obj build\obj\lib\tls_client.obj build\obj\lib\tls_extensions.obj build\obj\lib\tls_handshake_hash.obj build\obj\lib\tls_handshake_io.obj build\obj\lib\tls_handshake_state.obj build\obj\lib\tls_policy.obj build\obj\lib\tls_record.obj build\obj\lib\tls_server.obj build\obj\lib\tls_session.obj build\obj\lib\tls_session_key.obj build\obj\lib\tls_session_manager_memory.obj build\obj\lib\tls_suite_info.obj build\obj\lib\tls_text_policy.obj build\obj\lib\tls_version.obj build\obj\lib\utils_assert.obj build\obj\lib\utils_calendar.obj build\obj\lib\utils_charset.obj build\obj\lib\utils_cpuid.obj build\obj\lib\utils_cpuid_arm.obj build\obj\lib\utils_cpuid_ppc.obj build\obj\lib\utils_cpuid_x86.obj build\obj\lib\utils_ct_utils.obj build\obj\lib\utils_data_src.obj build\obj\lib\utils_dyn_load.obj build\obj\lib\utils_exceptn.obj build\obj\lib\utils_filesystem.obj build\obj\lib\utils_ghash.obj build\obj\lib\utils_ghash_cpu.obj build\obj\lib\utils_ghash_vperm.obj build\obj\lib\utils_http_util.obj build\obj\lib\utils_locking_allocator.obj build\obj\lib\utils_mem_ops.obj build\obj\lib\utils_mem_pool.obj build\obj\lib\utils_os_utils.obj build\obj\lib\utils_parsing.obj build\obj\lib\utils_poly_dbl.obj build\obj\lib\utils_read_cfg.obj build\obj\lib\utils_read_kv.obj build\obj\lib\utils_socket.obj build\obj\lib\utils_socket_udp.obj build\obj\lib\utils_socket_uri.obj build\obj\lib\utils_thread_utils_barrier.obj build\obj\lib\utils_thread_utils_rwlock.obj build\obj\lib\utils_thread_utils_semaphore.obj build\obj\lib\utils_thread_utils_thread_pool.obj build\obj\lib\utils_timer.obj build\obj\lib\utils_uuid.obj build\obj\lib\utils_version.obj build\obj\lib\x509_asn1_alt_name.obj build\obj\lib\x509_cert_status.obj build\obj\lib\x509_certstor.obj build\obj\lib\x509_certstor_flatfile.obj build\obj\lib\x509_certstor_sql.obj build\obj\lib\x509_certstor_system.obj build\obj\lib\x509_certstor_system_windows_certstor_windows.obj build\obj\lib\x509_crl_ent.obj build\obj\lib\x509_datastor.obj build\obj\lib\x509_key_constraint.obj build\obj\lib\x509_name_constraint.obj build\obj\lib\x509_ocsp.obj build\obj\lib\x509_ocsp_types.obj build\obj\lib\x509_pkcs10.obj build\obj\lib\x509_attribute.obj build\obj\lib\x509_ca.obj build\obj\lib\x509_crl.obj build\obj\lib\x509_dn.obj build\obj\lib\x509_dn_ub.obj build\obj\lib\x509_ext.obj build\obj\lib\x509_obj.obj build\obj\lib\x509_x509cert.obj build\obj\lib\x509_x509opt.obj build\obj\lib\x509_x509path.obj build\obj\lib\x509_x509self.obj

CLIOBJS = build\obj\cli\argon2.obj build\obj\cli\asn1.obj build\obj\cli\bcrypt.obj build\obj\cli\cc_enc.obj build\obj\cli\cli.obj build\obj\cli\cli_rng.obj build\obj\cli\codec.obj build\obj\cli\compress.obj build\obj\cli\encryption.obj build\obj\cli\entropy.obj build\obj\cli\hash.obj build\obj\cli\hmac.obj build\obj\cli\main.obj build\obj\cli\math.obj build\obj\cli\pbkdf.obj build\obj\cli\pk_crypt.obj build\obj\cli\psk.obj build\obj\cli\pubkey.obj build\obj\cli\roughtime.obj build\obj\cli\sandbox.obj build\obj\cli\speed.obj build\obj\cli\timing_tests.obj build\obj\cli\tls_client.obj build\obj\cli\tls_http_server.obj build\obj\cli\tls_proxy.obj build\obj\cli\tls_server.obj build\obj\cli\tls_utils.obj build\obj\cli\tss.obj build\obj\cli\utils.obj build\obj\cli\x509.obj

TESTOBJS = build\obj\test\main.obj build\obj\test\test_aead.obj build\obj\test\test_asn1.obj build\obj\test\test_bigint.obj build\obj\test\test_block.obj build\obj\test\test_blowfish.obj build\obj\test\test_c25519.obj build\obj\test\test_certstor.obj build\obj\test\test_certstor_flatfile.obj build\obj\test\test_certstor_system.obj build\obj\test\test_certstor_utils.obj build\obj\test\test_clang_bug.obj build\obj\test\test_compression.obj build\obj\test\test_cryptobox.obj build\obj\test\test_datastore.obj build\obj\test\test_dh.obj build\obj\test\test_dl_group.obj build\obj\test\test_dlies.obj build\obj\test\test_dsa.obj build\obj\test\test_ecc_pointmul.obj build\obj\test\test_ecdh.obj build\obj\test\test_ecdsa.obj build\obj\test\test_ecgdsa.obj build\obj\test\test_ecies.obj build\obj\test\test_eckcdsa.obj build\obj\test\test_ed25519.obj build\obj\test\test_elg.obj build\obj\test\test_entropy.obj build\obj\test\test_ffi.obj build\obj\test\test_filters.obj build\obj\test\test_fpe.obj build\obj\test\test_gf2m.obj build\obj\test\test_gost_3410.obj build\obj\test\test_hash.obj build\obj\test\test_hash_id.obj build\obj\test\test_kdf.obj build\obj\test\test_keywrap.obj build\obj\test\test_mac.obj build\obj\test\test_mceliece.obj build\obj\test\test_modes.obj build\obj\test\test_mp.obj build\obj\test\test_name_constraint.obj build\obj\test\test_newhope.obj build\obj\test\test_ocb.obj build\obj\test\test_ocsp.obj build\obj\test\test_octetstring.obj build\obj\test\test_oid.obj build\obj\test\test_os_utils.obj build\obj\test\test_otp.obj build\obj\test\test_package_transform.obj build\obj\test\test_pad.obj build\obj\test\test_passhash.obj build\obj\test\test_pbkdf.obj build\obj\test\test_pem.obj build\obj\test\test_pk_pad.obj build\obj\test\test_pkcs11_high_level.obj build\obj\test\test_pkcs11_low_level.obj build\obj\test\test_psk_db.obj build\obj\test\test_pubkey.obj build\obj\test\test_rfc6979.obj build\obj\test\test_rng.obj build\obj\test\test_rng_kat.obj build\obj\test\test_roughtime.obj build\obj\test\test_rsa.obj build\obj\test\test_runner.obj build\obj\test\test_simd.obj build\obj\test\test_siv.obj build\obj\test\test_sm2.obj build\obj\test\test_sodium.obj build\obj\test\test_srp6.obj build\obj\test\test_stream.obj build\obj\test\test_tests.obj build\obj\test\test_thread_utils.obj build\obj\test\test_tls.obj build\obj\test\test_tls_messages.obj build\obj\test\test_tls_stream_integration.obj build\obj\test\test_tpm.obj build\obj\test\test_tss.obj build\obj\test\test_uri.obj build\obj\test\test_utils.obj build\obj\test\test_workfactor.obj build\obj\test\test_x509_dn.obj build\obj\test\test_x509_path.obj build\obj\test\test_xmss.obj build\obj\test\tests.obj build\obj\test\unit_asio_stream.obj build\obj\test\unit_ecc.obj build\obj\test\unit_ecdh.obj build\obj\test\unit_ecdsa.obj build\obj\test\unit_tls.obj build\obj\test\unit_tls_policy.obj build\obj\test\unit_x509.obj

# Executable targets

$(CLI): $(LIBRARIES) $(CLIOBJS)
	$(EXE_LINK_CMD) $(ABI_FLAGS) $(CLIOBJS) $(LDFLAGS) $(EXE_LINKS_TO) /OUT:$@

$(TEST): $(LIBRARIES) $(TESTOBJS)
	$(EXE_LINK_CMD) $(ABI_FLAGS) $(TESTOBJS) $(LDFLAGS) $(EXE_LINKS_TO) /OUT:$@



# Library targets



./botan.dll: $(LIBOBJS)
	$(LINKER) /DLL $(ABI_FLAGS) $(LDFLAGS) $(LIBOBJS) $(LIB_LINKS_TO) /OUT:$@

# Build Commands

build\obj\lib\asn1_alg_id.obj: src/lib/asn1/alg_id.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/alg_id.cpp /Fo$@

build\obj\lib\asn1_obj.obj: src/lib/asn1/asn1_obj.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/asn1_obj.cpp /Fo$@

build\obj\lib\asn1_oid.obj: src/lib/asn1/asn1_oid.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/asn1_oid.cpp /Fo$@

build\obj\lib\asn1_print.obj: src/lib/asn1/asn1_print.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/asn1_print.cpp /Fo$@

build\obj\lib\asn1_str.obj: src/lib/asn1/asn1_str.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/asn1_str.cpp /Fo$@

build\obj\lib\asn1_time.obj: src/lib/asn1/asn1_time.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/asn1_time.cpp /Fo$@

build\obj\lib\asn1_ber_dec.obj: src/lib/asn1/ber_dec.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/ber_dec.cpp /Fo$@

build\obj\lib\asn1_der_enc.obj: src/lib/asn1/der_enc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/der_enc.cpp /Fo$@

build\obj\lib\asn1_oid_maps.obj: src/lib/asn1/oid_maps.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/oid_maps.cpp /Fo$@

build\obj\lib\asn1_oids.obj: src/lib/asn1/oids.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/asn1/oids.cpp /Fo$@

build\obj\lib\base_buf_comp.obj: src/lib/base/buf_comp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/base/buf_comp.cpp /Fo$@

build\obj\lib\base_scan_name.obj: src/lib/base/scan_name.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/base/scan_name.cpp /Fo$@

build\obj\lib\base_sym_algo.obj: src/lib/base/sym_algo.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/base/sym_algo.cpp /Fo$@

build\obj\lib\base_symkey.obj: src/lib/base/symkey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/base/symkey.cpp /Fo$@

build\obj\lib\block_aes.obj: src/lib/block/aes/aes.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/aes/aes.cpp /Fo$@

build\obj\lib\block_aes_ni.obj: src/lib/block/aes/aes_ni/aes_ni.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/aes/aes_ni/aes_ni.cpp /Fo$@

build\obj\lib\block_aria.obj: src/lib/block/aria/aria.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/aria/aria.cpp /Fo$@

build\obj\lib\block_cipher.obj: src/lib/block/block_cipher.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/block_cipher.cpp /Fo$@

build\obj\lib\block_blowfish.obj: src/lib/block/blowfish/blowfish.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/blowfish/blowfish.cpp /Fo$@

build\obj\lib\block_camellia.obj: src/lib/block/camellia/camellia.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/camellia/camellia.cpp /Fo$@

build\obj\lib\block_cascade.obj: src/lib/block/cascade/cascade.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/cascade/cascade.cpp /Fo$@

build\obj\lib\block_cast128.obj: src/lib/block/cast128/cast128.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/cast128/cast128.cpp /Fo$@

build\obj\lib\block_cast256.obj: src/lib/block/cast256/cast256.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/cast256/cast256.cpp /Fo$@

build\obj\lib\block_des.obj: src/lib/block/des/des.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/des/des.cpp /Fo$@

build\obj\lib\block_des_tab.obj: src/lib/block/des/des_tab.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/des/des_tab.cpp /Fo$@

build\obj\lib\block_des_desx.obj: src/lib/block/des/desx.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/des/desx.cpp /Fo$@

build\obj\lib\block_gost_28147.obj: src/lib/block/gost_28147/gost_28147.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/gost_28147/gost_28147.cpp /Fo$@

build\obj\lib\block_idea.obj: src/lib/block/idea/idea.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/idea/idea.cpp /Fo$@

build\obj\lib\block_idea_sse2.obj: src/lib/block/idea/idea_sse2/idea_sse2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/idea/idea_sse2/idea_sse2.cpp /Fo$@

build\obj\lib\block_kasumi.obj: src/lib/block/kasumi/kasumi.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/kasumi/kasumi.cpp /Fo$@

build\obj\lib\block_lion.obj: src/lib/block/lion/lion.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/lion/lion.cpp /Fo$@

build\obj\lib\block_misty1.obj: src/lib/block/misty1/misty1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/misty1/misty1.cpp /Fo$@

build\obj\lib\block_noekeon.obj: src/lib/block/noekeon/noekeon.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/noekeon/noekeon.cpp /Fo$@

build\obj\lib\block_noekeon_simd.obj: src/lib/block/noekeon/noekeon_simd/noekeon_simd.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/noekeon/noekeon_simd/noekeon_simd.cpp /Fo$@

build\obj\lib\block_seed.obj: src/lib/block/seed/seed.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/seed/seed.cpp /Fo$@

build\obj\lib\block_serpent.obj: src/lib/block/serpent/serpent.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/serpent/serpent.cpp /Fo$@

build\obj\lib\block_serpent_simd.obj: src/lib/block/serpent/serpent_simd/serpent_simd.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/serpent/serpent_simd/serpent_simd.cpp /Fo$@

build\obj\lib\block_shacal2.obj: src/lib/block/shacal2/shacal2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/shacal2/shacal2.cpp /Fo$@

build\obj\lib\block_shacal2_simd.obj: src/lib/block/shacal2/shacal2_simd/shacal2_simd.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/shacal2/shacal2_simd/shacal2_simd.cpp /Fo$@

build\obj\lib\block_shacal2_x86.obj: src/lib/block/shacal2/shacal2_x86/shacal2_x86.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/shacal2/shacal2_x86/shacal2_x86.cpp /Fo$@

build\obj\lib\block_sm4.obj: src/lib/block/sm4/sm4.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/sm4/sm4.cpp /Fo$@

build\obj\lib\block_threefish_512.obj: src/lib/block/threefish_512/threefish_512.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/threefish_512/threefish_512.cpp /Fo$@

build\obj\lib\block_twofish.obj: src/lib/block/twofish/twofish.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/twofish/twofish.cpp /Fo$@

build\obj\lib\block_twofish_tab.obj: src/lib/block/twofish/twofish_tab.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/twofish/twofish_tab.cpp /Fo$@

build\obj\lib\block_xtea.obj: src/lib/block/xtea/xtea.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/block/xtea/xtea.cpp /Fo$@

build\obj\lib\codec_base32.obj: src/lib/codec/base32/base32.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/codec/base32/base32.cpp /Fo$@

build\obj\lib\codec_base58.obj: src/lib/codec/base58/base58.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/codec/base58/base58.cpp /Fo$@

build\obj\lib\codec_base64.obj: src/lib/codec/base64/base64.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/codec/base64/base64.cpp /Fo$@

build\obj\lib\codec_hex.obj: src/lib/codec/hex/hex.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/codec/hex/hex.cpp /Fo$@

build\obj\lib\compat_sodium_25519.obj: src/lib/compat/sodium/sodium_25519.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_25519.cpp /Fo$@

build\obj\lib\compat_sodium_aead.obj: src/lib/compat/sodium/sodium_aead.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_aead.cpp /Fo$@

build\obj\lib\compat_sodium_auth.obj: src/lib/compat/sodium/sodium_auth.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_auth.cpp /Fo$@

build\obj\lib\compat_sodium_box.obj: src/lib/compat/sodium/sodium_box.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_box.cpp /Fo$@

build\obj\lib\compat_sodium_chacha.obj: src/lib/compat/sodium/sodium_chacha.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_chacha.cpp /Fo$@

build\obj\lib\compat_sodium_salsa.obj: src/lib/compat/sodium/sodium_salsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_salsa.cpp /Fo$@

build\obj\lib\compat_sodium_secretbox.obj: src/lib/compat/sodium/sodium_secretbox.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_secretbox.cpp /Fo$@

build\obj\lib\compat_sodium_utils.obj: src/lib/compat/sodium/sodium_utils.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/compat/sodium/sodium_utils.cpp /Fo$@

build\obj\lib\entropy_srcs.obj: src/lib/entropy/entropy_srcs.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/entropy/entropy_srcs.cpp /Fo$@

build\obj\lib\entropy_rdseed.obj: src/lib/entropy/rdseed/rdseed.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/entropy/rdseed/rdseed.cpp /Fo$@

build\obj\lib\entropy_win32_stats_es_win32.obj: src/lib/entropy/win32_stats/es_win32.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/entropy/win32_stats/es_win32.cpp /Fo$@

build\obj\lib\ffi.obj: src/lib/ffi/ffi.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi.cpp /Fo$@

build\obj\lib\ffi_block.obj: src/lib/ffi/ffi_block.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_block.cpp /Fo$@

build\obj\lib\ffi_cert.obj: src/lib/ffi/ffi_cert.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_cert.cpp /Fo$@

build\obj\lib\ffi_cipher.obj: src/lib/ffi/ffi_cipher.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_cipher.cpp /Fo$@

build\obj\lib\ffi_fpe.obj: src/lib/ffi/ffi_fpe.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_fpe.cpp /Fo$@

build\obj\lib\ffi_hash.obj: src/lib/ffi/ffi_hash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_hash.cpp /Fo$@

build\obj\lib\ffi_hotp.obj: src/lib/ffi/ffi_hotp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_hotp.cpp /Fo$@

build\obj\lib\ffi_kdf.obj: src/lib/ffi/ffi_kdf.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_kdf.cpp /Fo$@

build\obj\lib\ffi_keywrap.obj: src/lib/ffi/ffi_keywrap.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_keywrap.cpp /Fo$@

build\obj\lib\ffi_mac.obj: src/lib/ffi/ffi_mac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_mac.cpp /Fo$@

build\obj\lib\ffi_mp.obj: src/lib/ffi/ffi_mp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_mp.cpp /Fo$@

build\obj\lib\ffi_pk_op.obj: src/lib/ffi/ffi_pk_op.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_pk_op.cpp /Fo$@

build\obj\lib\ffi_pkey.obj: src/lib/ffi/ffi_pkey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_pkey.cpp /Fo$@

build\obj\lib\ffi_pkey_algs.obj: src/lib/ffi/ffi_pkey_algs.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_pkey_algs.cpp /Fo$@

build\obj\lib\ffi_rng.obj: src/lib/ffi/ffi_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_rng.cpp /Fo$@

build\obj\lib\ffi_totp.obj: src/lib/ffi/ffi_totp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/ffi/ffi_totp.cpp /Fo$@

build\obj\lib\filters_algo_filt.obj: src/lib/filters/algo_filt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/algo_filt.cpp /Fo$@

build\obj\lib\filters_b64_filt.obj: src/lib/filters/b64_filt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/b64_filt.cpp /Fo$@

build\obj\lib\filters_basefilt.obj: src/lib/filters/basefilt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/basefilt.cpp /Fo$@

build\obj\lib\filters_buf_filt.obj: src/lib/filters/buf_filt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/buf_filt.cpp /Fo$@

build\obj\lib\filters_cipher_filter.obj: src/lib/filters/cipher_filter.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/cipher_filter.cpp /Fo$@

build\obj\lib\filters_comp_filter.obj: src/lib/filters/comp_filter.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/comp_filter.cpp /Fo$@

build\obj\lib\filters_data_snk.obj: src/lib/filters/data_snk.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/data_snk.cpp /Fo$@

build\obj\lib\filters_filter.obj: src/lib/filters/filter.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/filter.cpp /Fo$@

build\obj\lib\filters_hex_filt.obj: src/lib/filters/hex_filt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/hex_filt.cpp /Fo$@

build\obj\lib\filters_out_buf.obj: src/lib/filters/out_buf.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/out_buf.cpp /Fo$@

build\obj\lib\filters_pipe.obj: src/lib/filters/pipe.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/pipe.cpp /Fo$@

build\obj\lib\filters_pipe_io.obj: src/lib/filters/pipe_io.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/pipe_io.cpp /Fo$@

build\obj\lib\filters_pipe_rw.obj: src/lib/filters/pipe_rw.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/pipe_rw.cpp /Fo$@

build\obj\lib\filters_secqueue.obj: src/lib/filters/secqueue.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/secqueue.cpp /Fo$@

build\obj\lib\filters_threaded_fork.obj: src/lib/filters/threaded_fork.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/filters/threaded_fork.cpp /Fo$@

build\obj\lib\hash_blake2_blake2b.obj: src/lib/hash/blake2/blake2b.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/blake2/blake2b.cpp /Fo$@

build\obj\lib\hash_checksum_adler32.obj: src/lib/hash/checksum/adler32/adler32.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/checksum/adler32/adler32.cpp /Fo$@

build\obj\lib\hash_checksum_crc24.obj: src/lib/hash/checksum/crc24/crc24.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/checksum/crc24/crc24.cpp /Fo$@

build\obj\lib\hash_checksum_crc32.obj: src/lib/hash/checksum/crc32/crc32.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/checksum/crc32/crc32.cpp /Fo$@

build\obj\lib\hash_comb4p.obj: src/lib/hash/comb4p/comb4p.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/comb4p/comb4p.cpp /Fo$@

build\obj\lib\hash_gost_3411.obj: src/lib/hash/gost_3411/gost_3411.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/gost_3411/gost_3411.cpp /Fo$@

build\obj\lib\hash.obj: src/lib/hash/hash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/hash.cpp /Fo$@

build\obj\lib\hash_keccak.obj: src/lib/hash/keccak/keccak.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/keccak/keccak.cpp /Fo$@

build\obj\lib\hash_md4.obj: src/lib/hash/md4/md4.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/md4/md4.cpp /Fo$@

build\obj\lib\hash_md5.obj: src/lib/hash/md5/md5.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/md5/md5.cpp /Fo$@

build\obj\lib\hash_mdx_hash.obj: src/lib/hash/mdx_hash/mdx_hash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/mdx_hash/mdx_hash.cpp /Fo$@

build\obj\lib\hash_par_hash.obj: src/lib/hash/par_hash/par_hash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/par_hash/par_hash.cpp /Fo$@

build\obj\lib\hash_rmd160.obj: src/lib/hash/rmd160/rmd160.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/rmd160/rmd160.cpp /Fo$@

build\obj\lib\hash_sha1_sha160.obj: src/lib/hash/sha1/sha160.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha1/sha160.cpp /Fo$@

build\obj\lib\hash_sha1_sse2.obj: src/lib/hash/sha1/sha1_sse2/sha1_sse2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha1/sha1_sse2/sha1_sse2.cpp /Fo$@

build\obj\lib\hash_sha1_x86.obj: src/lib/hash/sha1/sha1_x86/sha1_x86.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha1/sha1_x86/sha1_x86.cpp /Fo$@

build\obj\lib\hash_sha2_32.obj: src/lib/hash/sha2_32/sha2_32.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha2_32/sha2_32.cpp /Fo$@

build\obj\lib\hash_sha2_32_sha2_32_x86.obj: src/lib/hash/sha2_32/sha2_32_x86/sha2_32_x86.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha2_32/sha2_32_x86/sha2_32_x86.cpp /Fo$@

build\obj\lib\hash_sha2_64.obj: src/lib/hash/sha2_64/sha2_64.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha2_64/sha2_64.cpp /Fo$@

build\obj\lib\hash_sha3.obj: src/lib/hash/sha3/sha3.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sha3/sha3.cpp /Fo$@

build\obj\lib\hash_shake.obj: src/lib/hash/shake/shake.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/shake/shake.cpp /Fo$@

build\obj\lib\hash_skein_512.obj: src/lib/hash/skein/skein_512.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/skein/skein_512.cpp /Fo$@

build\obj\lib\hash_sm3.obj: src/lib/hash/sm3/sm3.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/sm3/sm3.cpp /Fo$@

build\obj\lib\hash_streebog.obj: src/lib/hash/streebog/streebog.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/streebog/streebog.cpp /Fo$@

build\obj\lib\hash_streebog_precalc.obj: src/lib/hash/streebog/streebog_precalc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/streebog/streebog_precalc.cpp /Fo$@

build\obj\lib\hash_tiger_tig_tab.obj: src/lib/hash/tiger/tig_tab.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/tiger/tig_tab.cpp /Fo$@

build\obj\lib\hash_tiger.obj: src/lib/hash/tiger/tiger.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/tiger/tiger.cpp /Fo$@

build\obj\lib\hash_whirlpool.obj: src/lib/hash/whirlpool/whirlpool.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/whirlpool/whirlpool.cpp /Fo$@

build\obj\lib\hash_whirlpool_whrl_tab.obj: src/lib/hash/whirlpool/whrl_tab.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/hash/whirlpool/whrl_tab.cpp /Fo$@

build\obj\lib\kdf_hkdf.obj: src/lib/kdf/hkdf/hkdf.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/hkdf/hkdf.cpp /Fo$@

build\obj\lib\kdf.obj: src/lib/kdf/kdf.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/kdf.cpp /Fo$@

build\obj\lib\kdf_kdf1.obj: src/lib/kdf/kdf1/kdf1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/kdf1/kdf1.cpp /Fo$@

build\obj\lib\kdf_kdf1_iso18033.obj: src/lib/kdf/kdf1_iso18033/kdf1_iso18033.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/kdf1_iso18033/kdf1_iso18033.cpp /Fo$@

build\obj\lib\kdf_kdf2.obj: src/lib/kdf/kdf2/kdf2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/kdf2/kdf2.cpp /Fo$@

build\obj\lib\kdf_prf_tls.obj: src/lib/kdf/prf_tls/prf_tls.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/prf_tls/prf_tls.cpp /Fo$@

build\obj\lib\kdf_prf_x942.obj: src/lib/kdf/prf_x942/prf_x942.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/prf_x942/prf_x942.cpp /Fo$@

build\obj\lib\kdf_sp800_108.obj: src/lib/kdf/sp800_108/sp800_108.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/sp800_108/sp800_108.cpp /Fo$@

build\obj\lib\kdf_sp800_56a.obj: src/lib/kdf/sp800_56a/sp800_56a.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/sp800_56a/sp800_56a.cpp /Fo$@

build\obj\lib\kdf_sp800_56c.obj: src/lib/kdf/sp800_56c/sp800_56c.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/kdf/sp800_56c/sp800_56c.cpp /Fo$@

build\obj\lib\mac_cbc_mac.obj: src/lib/mac/cbc_mac/cbc_mac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/cbc_mac/cbc_mac.cpp /Fo$@

build\obj\lib\mac_cmac.obj: src/lib/mac/cmac/cmac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/cmac/cmac.cpp /Fo$@

build\obj\lib\mac_gmac.obj: src/lib/mac/gmac/gmac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/gmac/gmac.cpp /Fo$@

build\obj\lib\mac_hmac.obj: src/lib/mac/hmac/hmac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/hmac/hmac.cpp /Fo$@

build\obj\lib\mac.obj: src/lib/mac/mac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/mac.cpp /Fo$@

build\obj\lib\mac_poly1305.obj: src/lib/mac/poly1305/poly1305.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/poly1305/poly1305.cpp /Fo$@

build\obj\lib\mac_siphash.obj: src/lib/mac/siphash/siphash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/siphash/siphash.cpp /Fo$@

build\obj\lib\mac_x919_mac.obj: src/lib/mac/x919_mac/x919_mac.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/mac/x919_mac/x919_mac.cpp /Fo$@

build\obj\lib\math_bigint_big_code.obj: src/lib/math/bigint/big_code.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/big_code.cpp /Fo$@

build\obj\lib\math_bigint_big_io.obj: src/lib/math/bigint/big_io.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/big_io.cpp /Fo$@

build\obj\lib\math_bigint_big_ops2.obj: src/lib/math/bigint/big_ops2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/big_ops2.cpp /Fo$@

build\obj\lib\math_bigint_big_ops3.obj: src/lib/math/bigint/big_ops3.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/big_ops3.cpp /Fo$@

build\obj\lib\math_bigint_big_rand.obj: src/lib/math/bigint/big_rand.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/big_rand.cpp /Fo$@

build\obj\lib\math_bigint.obj: src/lib/math/bigint/bigint.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/bigint.cpp /Fo$@

build\obj\lib\math_bigint_divide.obj: src/lib/math/bigint/divide.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/bigint/divide.cpp /Fo$@

build\obj\lib\math_mp_comba.obj: src/lib/math/mp/mp_comba.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/mp/mp_comba.cpp /Fo$@

build\obj\lib\math_mp_karat.obj: src/lib/math/mp/mp_karat.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/mp/mp_karat.cpp /Fo$@

build\obj\lib\math_mp_monty.obj: src/lib/math/mp/mp_monty.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/mp/mp_monty.cpp /Fo$@

build\obj\lib\math_mp_monty_n.obj: src/lib/math/mp/mp_monty_n.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/mp/mp_monty_n.cpp /Fo$@

build\obj\lib\math_numbertheory_dsa_gen.obj: src/lib/math/numbertheory/dsa_gen.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/dsa_gen.cpp /Fo$@

build\obj\lib\math_numbertheory_jacobi.obj: src/lib/math/numbertheory/jacobi.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/jacobi.cpp /Fo$@

build\obj\lib\math_numbertheory_make_prm.obj: src/lib/math/numbertheory/make_prm.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/make_prm.cpp /Fo$@

build\obj\lib\math_numbertheory_mod_inv.obj: src/lib/math/numbertheory/mod_inv.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/mod_inv.cpp /Fo$@

build\obj\lib\math_numbertheory_monty.obj: src/lib/math/numbertheory/monty.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/monty.cpp /Fo$@

build\obj\lib\math_numbertheory_monty_exp.obj: src/lib/math/numbertheory/monty_exp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/monty_exp.cpp /Fo$@

build\obj\lib\math_numbertheory_mp_numth.obj: src/lib/math/numbertheory/mp_numth.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/mp_numth.cpp /Fo$@

build\obj\lib\math_numbertheory_nistp_redc.obj: src/lib/math/numbertheory/nistp_redc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/nistp_redc.cpp /Fo$@

build\obj\lib\math_numbertheory_numthry.obj: src/lib/math/numbertheory/numthry.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/numthry.cpp /Fo$@

build\obj\lib\math_numbertheory_pow_mod.obj: src/lib/math/numbertheory/pow_mod.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/pow_mod.cpp /Fo$@

build\obj\lib\math_numbertheory_primality.obj: src/lib/math/numbertheory/primality.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/primality.cpp /Fo$@

build\obj\lib\math_numbertheory_primes.obj: src/lib/math/numbertheory/primes.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/primes.cpp /Fo$@

build\obj\lib\math_numbertheory_reducer.obj: src/lib/math/numbertheory/reducer.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/reducer.cpp /Fo$@

build\obj\lib\math_numbertheory_ressol.obj: src/lib/math/numbertheory/ressol.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/math/numbertheory/ressol.cpp /Fo$@

build\obj\lib\misc_aont_package.obj: src/lib/misc/aont/package.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/aont/package.cpp /Fo$@

build\obj\lib\misc_cryptobox.obj: src/lib/misc/cryptobox/cryptobox.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/cryptobox/cryptobox.cpp /Fo$@

build\obj\lib\misc_fpe_fe1.obj: src/lib/misc/fpe_fe1/fpe_fe1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/fpe_fe1/fpe_fe1.cpp /Fo$@

build\obj\lib\misc_hotp.obj: src/lib/misc/hotp/hotp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/hotp/hotp.cpp /Fo$@

build\obj\lib\misc_hotp_totp.obj: src/lib/misc/hotp/totp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/hotp/totp.cpp /Fo$@

build\obj\lib\misc_nist_keywrap.obj: src/lib/misc/nist_keywrap/nist_keywrap.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/nist_keywrap/nist_keywrap.cpp /Fo$@

build\obj\lib\misc_rfc3394.obj: src/lib/misc/rfc3394/rfc3394.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/rfc3394/rfc3394.cpp /Fo$@

build\obj\lib\misc_roughtime.obj: src/lib/misc/roughtime/roughtime.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/roughtime/roughtime.cpp /Fo$@

build\obj\lib\misc_srp6.obj: src/lib/misc/srp6/srp6.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/srp6/srp6.cpp /Fo$@

build\obj\lib\misc_tss.obj: src/lib/misc/tss/tss.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/misc/tss/tss.cpp /Fo$@

build\obj\lib\modes_aead.obj: src/lib/modes/aead/aead.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/aead.cpp /Fo$@

build\obj\lib\modes_aead_ccm.obj: src/lib/modes/aead/ccm/ccm.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/ccm/ccm.cpp /Fo$@

build\obj\lib\modes_aead_chacha20poly1305.obj: src/lib/modes/aead/chacha20poly1305/chacha20poly1305.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/chacha20poly1305/chacha20poly1305.cpp /Fo$@

build\obj\lib\modes_aead_eax.obj: src/lib/modes/aead/eax/eax.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/eax/eax.cpp /Fo$@

build\obj\lib\modes_aead_gcm.obj: src/lib/modes/aead/gcm/gcm.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/gcm/gcm.cpp /Fo$@

build\obj\lib\modes_aead_ocb.obj: src/lib/modes/aead/ocb/ocb.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/ocb/ocb.cpp /Fo$@

build\obj\lib\modes_aead_siv.obj: src/lib/modes/aead/siv/siv.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/aead/siv/siv.cpp /Fo$@

build\obj\lib\modes_cbc.obj: src/lib/modes/cbc/cbc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/cbc/cbc.cpp /Fo$@

build\obj\lib\modes_cfb.obj: src/lib/modes/cfb/cfb.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/cfb/cfb.cpp /Fo$@

build\obj\lib\modes_cipher_mode.obj: src/lib/modes/cipher_mode.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/cipher_mode.cpp /Fo$@

build\obj\lib\modes_mode_pad.obj: src/lib/modes/mode_pad/mode_pad.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/mode_pad/mode_pad.cpp /Fo$@

build\obj\lib\modes_xts.obj: src/lib/modes/xts/xts.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/modes/xts/xts.cpp /Fo$@

build\obj\lib\passhash_bcrypt.obj: src/lib/passhash/bcrypt/bcrypt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/passhash/bcrypt/bcrypt.cpp /Fo$@

build\obj\lib\passhash_passhash9.obj: src/lib/passhash/passhash9/passhash9.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/passhash/passhash9/passhash9.cpp /Fo$@

build\obj\lib\pbkdf_argon2.obj: src/lib/pbkdf/argon2/argon2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/argon2/argon2.cpp /Fo$@

build\obj\lib\pbkdf_argon2_argon2fmt.obj: src/lib/pbkdf/argon2/argon2fmt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/argon2/argon2fmt.cpp /Fo$@

build\obj\lib\pbkdf_argon2_argon2pwhash.obj: src/lib/pbkdf/argon2/argon2pwhash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/argon2/argon2pwhash.cpp /Fo$@

build\obj\lib\pbkdf_bcrypt_pbkdf.obj: src/lib/pbkdf/bcrypt_pbkdf/bcrypt_pbkdf.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/bcrypt_pbkdf/bcrypt_pbkdf.cpp /Fo$@

build\obj\lib\pbkdf.obj: src/lib/pbkdf/pbkdf.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/pbkdf.cpp /Fo$@

build\obj\lib\pbkdf_pbkdf1.obj: src/lib/pbkdf/pbkdf1/pbkdf1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/pbkdf1/pbkdf1.cpp /Fo$@

build\obj\lib\pbkdf_pbkdf2.obj: src/lib/pbkdf/pbkdf2/pbkdf2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/pbkdf2/pbkdf2.cpp /Fo$@

build\obj\lib\pbkdf_pgp_s2k.obj: src/lib/pbkdf/pgp_s2k/pgp_s2k.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/pgp_s2k/pgp_s2k.cpp /Fo$@

build\obj\lib\pbkdf_pwdhash.obj: src/lib/pbkdf/pwdhash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/pwdhash.cpp /Fo$@

build\obj\lib\pbkdf_scrypt.obj: src/lib/pbkdf/scrypt/scrypt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pbkdf/scrypt/scrypt.cpp /Fo$@

build\obj\lib\pk_pad_eme.obj: src/lib/pk_pad/eme.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/eme.cpp /Fo$@

build\obj\lib\pk_pad_eme_oaep_oaep.obj: src/lib/pk_pad/eme_oaep/oaep.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/eme_oaep/oaep.cpp /Fo$@

build\obj\lib\pk_pad_eme_pkcs1_eme_pkcs.obj: src/lib/pk_pad/eme_pkcs1/eme_pkcs.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/eme_pkcs1/eme_pkcs.cpp /Fo$@

build\obj\lib\pk_pad_eme_raw.obj: src/lib/pk_pad/eme_raw/eme_raw.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/eme_raw/eme_raw.cpp /Fo$@

build\obj\lib\pk_pad_emsa.obj: src/lib/pk_pad/emsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/emsa.cpp /Fo$@

build\obj\lib\pk_pad_emsa1.obj: src/lib/pk_pad/emsa1/emsa1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/emsa1/emsa1.cpp /Fo$@

build\obj\lib\pk_pad_emsa_pkcs1.obj: src/lib/pk_pad/emsa_pkcs1/emsa_pkcs1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/emsa_pkcs1/emsa_pkcs1.cpp /Fo$@

build\obj\lib\pk_pad_emsa_pssr_pssr.obj: src/lib/pk_pad/emsa_pssr/pssr.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/emsa_pssr/pssr.cpp /Fo$@

build\obj\lib\pk_pad_emsa_raw.obj: src/lib/pk_pad/emsa_raw/emsa_raw.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/emsa_raw/emsa_raw.cpp /Fo$@

build\obj\lib\pk_pad_emsa_x931.obj: src/lib/pk_pad/emsa_x931/emsa_x931.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/emsa_x931/emsa_x931.cpp /Fo$@

build\obj\lib\pk_pad_hash_id.obj: src/lib/pk_pad/hash_id/hash_id.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/hash_id/hash_id.cpp /Fo$@

build\obj\lib\pk_pad_iso9796.obj: src/lib/pk_pad/iso9796/iso9796.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/iso9796/iso9796.cpp /Fo$@

build\obj\lib\pk_pad_mgf1.obj: src/lib/pk_pad/mgf1/mgf1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/mgf1/mgf1.cpp /Fo$@

build\obj\lib\pk_pad_padding.obj: src/lib/pk_pad/padding.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pk_pad/padding.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11.obj: src/lib/prov/pkcs11/p11.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_ecc_key.obj: src/lib/prov/pkcs11/p11_ecc_key.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_ecc_key.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_ecdh.obj: src/lib/prov/pkcs11/p11_ecdh.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_ecdh.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_ecdsa.obj: src/lib/prov/pkcs11/p11_ecdsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_ecdsa.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_mechanism.obj: src/lib/prov/pkcs11/p11_mechanism.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_mechanism.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_module.obj: src/lib/prov/pkcs11/p11_module.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_module.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_object.obj: src/lib/prov/pkcs11/p11_object.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_object.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_randomgenerator.obj: src/lib/prov/pkcs11/p11_randomgenerator.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_randomgenerator.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_rsa.obj: src/lib/prov/pkcs11/p11_rsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_rsa.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_session.obj: src/lib/prov/pkcs11/p11_session.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_session.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_slot.obj: src/lib/prov/pkcs11/p11_slot.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_slot.cpp /Fo$@

build\obj\lib\prov_pkcs11_p11_x509.obj: src/lib/prov/pkcs11/p11_x509.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/prov/pkcs11/p11_x509.cpp /Fo$@

build\obj\lib\psk_db.obj: src/lib/psk_db/psk_db.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/psk_db/psk_db.cpp /Fo$@

build\obj\lib\psk_db_psk_db_sql.obj: src/lib/psk_db/psk_db_sql.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/psk_db/psk_db_sql.cpp /Fo$@

build\obj\lib\pubkey_blinding.obj: src/lib/pubkey/blinding.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/blinding.cpp /Fo$@

build\obj\lib\pubkey_cecpq1.obj: src/lib/pubkey/cecpq1/cecpq1.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/cecpq1/cecpq1.cpp /Fo$@

build\obj\lib\pubkey_curve25519.obj: src/lib/pubkey/curve25519/curve25519.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/curve25519/curve25519.cpp /Fo$@

build\obj\lib\pubkey_curve25519_donna.obj: src/lib/pubkey/curve25519/donna.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/curve25519/donna.cpp /Fo$@

build\obj\lib\pubkey_dh.obj: src/lib/pubkey/dh/dh.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/dh/dh.cpp /Fo$@

build\obj\lib\pubkey_dl_algo.obj: src/lib/pubkey/dl_algo/dl_algo.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/dl_algo/dl_algo.cpp /Fo$@

build\obj\lib\pubkey_dl_group.obj: src/lib/pubkey/dl_group/dl_group.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/dl_group/dl_group.cpp /Fo$@

build\obj\lib\pubkey_dl_group_dl_named.obj: src/lib/pubkey/dl_group/dl_named.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/dl_group/dl_named.cpp /Fo$@

build\obj\lib\pubkey_dlies.obj: src/lib/pubkey/dlies/dlies.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/dlies/dlies.cpp /Fo$@

build\obj\lib\pubkey_dsa.obj: src/lib/pubkey/dsa/dsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/dsa/dsa.cpp /Fo$@

build\obj\lib\pubkey_ec_group_curve_gfp.obj: src/lib/pubkey/ec_group/curve_gfp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ec_group/curve_gfp.cpp /Fo$@

build\obj\lib\pubkey_ec_group.obj: src/lib/pubkey/ec_group/ec_group.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ec_group/ec_group.cpp /Fo$@

build\obj\lib\pubkey_ec_group_ec_named.obj: src/lib/pubkey/ec_group/ec_named.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ec_group/ec_named.cpp /Fo$@

build\obj\lib\pubkey_ec_group_point_gfp.obj: src/lib/pubkey/ec_group/point_gfp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ec_group/point_gfp.cpp /Fo$@

build\obj\lib\pubkey_ec_group_point_mul.obj: src/lib/pubkey/ec_group/point_mul.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ec_group/point_mul.cpp /Fo$@

build\obj\lib\pubkey_ecc_key.obj: src/lib/pubkey/ecc_key/ecc_key.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ecc_key/ecc_key.cpp /Fo$@

build\obj\lib\pubkey_ecdh.obj: src/lib/pubkey/ecdh/ecdh.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ecdh/ecdh.cpp /Fo$@

build\obj\lib\pubkey_ecdsa.obj: src/lib/pubkey/ecdsa/ecdsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ecdsa/ecdsa.cpp /Fo$@

build\obj\lib\pubkey_ecgdsa.obj: src/lib/pubkey/ecgdsa/ecgdsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ecgdsa/ecgdsa.cpp /Fo$@

build\obj\lib\pubkey_ecies.obj: src/lib/pubkey/ecies/ecies.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ecies/ecies.cpp /Fo$@

build\obj\lib\pubkey_eckcdsa.obj: src/lib/pubkey/eckcdsa/eckcdsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/eckcdsa/eckcdsa.cpp /Fo$@

build\obj\lib\pubkey_ed25519.obj: src/lib/pubkey/ed25519/ed25519.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ed25519/ed25519.cpp /Fo$@

build\obj\lib\pubkey_ed25519_fe.obj: src/lib/pubkey/ed25519/ed25519_fe.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ed25519/ed25519_fe.cpp /Fo$@

build\obj\lib\pubkey_ed25519_key.obj: src/lib/pubkey/ed25519/ed25519_key.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ed25519/ed25519_key.cpp /Fo$@

build\obj\lib\pubkey_ed25519_ge.obj: src/lib/pubkey/ed25519/ge.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ed25519/ge.cpp /Fo$@

build\obj\lib\pubkey_ed25519_sc_muladd.obj: src/lib/pubkey/ed25519/sc_muladd.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ed25519/sc_muladd.cpp /Fo$@

build\obj\lib\pubkey_ed25519_sc_reduce.obj: src/lib/pubkey/ed25519/sc_reduce.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/ed25519/sc_reduce.cpp /Fo$@

build\obj\lib\pubkey_elgamal.obj: src/lib/pubkey/elgamal/elgamal.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/elgamal/elgamal.cpp /Fo$@

build\obj\lib\pubkey_gost_3410.obj: src/lib/pubkey/gost_3410/gost_3410.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/gost_3410/gost_3410.cpp /Fo$@

build\obj\lib\pubkey_keypair.obj: src/lib/pubkey/keypair/keypair.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/keypair/keypair.cpp /Fo$@

build\obj\lib\pubkey_mce_code_based_key_gen.obj: src/lib/pubkey/mce/code_based_key_gen.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/code_based_key_gen.cpp /Fo$@

build\obj\lib\pubkey_mce_gf2m_rootfind_dcmp.obj: src/lib/pubkey/mce/gf2m_rootfind_dcmp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/gf2m_rootfind_dcmp.cpp /Fo$@

build\obj\lib\pubkey_mce_gf2m_small_m.obj: src/lib/pubkey/mce/gf2m_small_m.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/gf2m_small_m.cpp /Fo$@

build\obj\lib\pubkey_mce_goppa_code.obj: src/lib/pubkey/mce/goppa_code.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/goppa_code.cpp /Fo$@

build\obj\lib\pubkey_mce_workfactor.obj: src/lib/pubkey/mce/mce_workfactor.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/mce_workfactor.cpp /Fo$@

build\obj\lib\pubkey_mce_mceliece.obj: src/lib/pubkey/mce/mceliece.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/mceliece.cpp /Fo$@

build\obj\lib\pubkey_mce_mceliece_key.obj: src/lib/pubkey/mce/mceliece_key.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/mceliece_key.cpp /Fo$@

build\obj\lib\pubkey_mce_polyn_gf2m.obj: src/lib/pubkey/mce/polyn_gf2m.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mce/polyn_gf2m.cpp /Fo$@

build\obj\lib\pubkey_mceies.obj: src/lib/pubkey/mceies/mceies.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/mceies/mceies.cpp /Fo$@

build\obj\lib\pubkey_newhope.obj: src/lib/pubkey/newhope/newhope.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/newhope/newhope.cpp /Fo$@

build\obj\lib\pubkey_pbes2.obj: src/lib/pubkey/pbes2/pbes2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pbes2/pbes2.cpp /Fo$@

build\obj\lib\pubkey_pem.obj: src/lib/pubkey/pem/pem.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pem/pem.cpp /Fo$@

build\obj\lib\pubkey_pk_algs.obj: src/lib/pubkey/pk_algs.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pk_algs.cpp /Fo$@

build\obj\lib\pubkey_pk_keys.obj: src/lib/pubkey/pk_keys.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pk_keys.cpp /Fo$@

build\obj\lib\pubkey_pk_ops.obj: src/lib/pubkey/pk_ops.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pk_ops.cpp /Fo$@

build\obj\lib\pubkey_pkcs8.obj: src/lib/pubkey/pkcs8.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pkcs8.cpp /Fo$@

build\obj\lib\pubkey.obj: src/lib/pubkey/pubkey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/pubkey.cpp /Fo$@

build\obj\lib\pubkey_rfc6979.obj: src/lib/pubkey/rfc6979/rfc6979.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/rfc6979/rfc6979.cpp /Fo$@

build\obj\lib\pubkey_rsa.obj: src/lib/pubkey/rsa/rsa.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/rsa/rsa.cpp /Fo$@

build\obj\lib\pubkey_sm2.obj: src/lib/pubkey/sm2/sm2.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/sm2/sm2.cpp /Fo$@

build\obj\lib\pubkey_sm2_enc.obj: src/lib/pubkey/sm2/sm2_enc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/sm2/sm2_enc.cpp /Fo$@

build\obj\lib\pubkey_workfactor.obj: src/lib/pubkey/workfactor.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/workfactor.cpp /Fo$@

build\obj\lib\pubkey_x509_key.obj: src/lib/pubkey/x509_key.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/x509_key.cpp /Fo$@

build\obj\lib\pubkey_xmss_common_ops.obj: src/lib/pubkey/xmss/xmss_common_ops.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_common_ops.cpp /Fo$@

build\obj\lib\pubkey_xmss_hash.obj: src/lib/pubkey/xmss/xmss_hash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_hash.cpp /Fo$@

build\obj\lib\pubkey_xmss_index_registry.obj: src/lib/pubkey/xmss/xmss_index_registry.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_index_registry.cpp /Fo$@

build\obj\lib\pubkey_xmss_parameters.obj: src/lib/pubkey/xmss/xmss_parameters.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_parameters.cpp /Fo$@

build\obj\lib\pubkey_xmss_privatekey.obj: src/lib/pubkey/xmss/xmss_privatekey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_privatekey.cpp /Fo$@

build\obj\lib\pubkey_xmss_publickey.obj: src/lib/pubkey/xmss/xmss_publickey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_publickey.cpp /Fo$@

build\obj\lib\pubkey_xmss_signature.obj: src/lib/pubkey/xmss/xmss_signature.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_signature.cpp /Fo$@

build\obj\lib\pubkey_xmss_signature_operation.obj: src/lib/pubkey/xmss/xmss_signature_operation.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_signature_operation.cpp /Fo$@

build\obj\lib\pubkey_xmss_verification_operation.obj: src/lib/pubkey/xmss/xmss_verification_operation.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_verification_operation.cpp /Fo$@

build\obj\lib\pubkey_xmss_wots_parameters.obj: src/lib/pubkey/xmss/xmss_wots_parameters.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_wots_parameters.cpp /Fo$@

build\obj\lib\pubkey_xmss_wots_privatekey.obj: src/lib/pubkey/xmss/xmss_wots_privatekey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_wots_privatekey.cpp /Fo$@

build\obj\lib\pubkey_xmss_wots_publickey.obj: src/lib/pubkey/xmss/xmss_wots_publickey.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/pubkey/xmss/xmss_wots_publickey.cpp /Fo$@

build\obj\lib\rng_auto_rng.obj: src/lib/rng/auto_rng/auto_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/auto_rng/auto_rng.cpp /Fo$@

build\obj\lib\rng_chacha_rng.obj: src/lib/rng/chacha_rng/chacha_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/chacha_rng/chacha_rng.cpp /Fo$@

build\obj\lib\rng_hmac_drbg.obj: src/lib/rng/hmac_drbg/hmac_drbg.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/hmac_drbg/hmac_drbg.cpp /Fo$@

build\obj\lib\rng_processor_rng.obj: src/lib/rng/processor_rng/processor_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/processor_rng/processor_rng.cpp /Fo$@

build\obj\lib\rng_rdrand_rng.obj: src/lib/rng/rdrand_rng/rdrand_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/rdrand_rng/rdrand_rng.cpp /Fo$@

build\obj\lib\rng.obj: src/lib/rng/rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/rng.cpp /Fo$@

build\obj\lib\rng_stateful_rng.obj: src/lib/rng/stateful_rng/stateful_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/stateful_rng/stateful_rng.cpp /Fo$@

build\obj\lib\rng_system_rng.obj: src/lib/rng/system_rng/system_rng.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/rng/system_rng/system_rng.cpp /Fo$@

build\obj\lib\stream_chacha.obj: src/lib/stream/chacha/chacha.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/chacha/chacha.cpp /Fo$@

build\obj\lib\stream_chacha_simd32.obj: src/lib/stream/chacha/chacha_simd32/chacha_simd32.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/chacha/chacha_simd32/chacha_simd32.cpp /Fo$@

build\obj\lib\stream_ctr.obj: src/lib/stream/ctr/ctr.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/ctr/ctr.cpp /Fo$@

build\obj\lib\stream_ofb.obj: src/lib/stream/ofb/ofb.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/ofb/ofb.cpp /Fo$@

build\obj\lib\stream_rc4.obj: src/lib/stream/rc4/rc4.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/rc4/rc4.cpp /Fo$@

build\obj\lib\stream_salsa20.obj: src/lib/stream/salsa20/salsa20.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/salsa20/salsa20.cpp /Fo$@

build\obj\lib\stream_shake_cipher.obj: src/lib/stream/shake_cipher/shake_cipher.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/shake_cipher/shake_cipher.cpp /Fo$@

build\obj\lib\stream_cipher.obj: src/lib/stream/stream_cipher.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/stream/stream_cipher.cpp /Fo$@

build\obj\lib\tls_credentials_manager.obj: src/lib/tls/credentials_manager.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/credentials_manager.cpp /Fo$@

build\obj\lib\tls_msg_cert_req.obj: src/lib/tls/msg_cert_req.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_cert_req.cpp /Fo$@

build\obj\lib\tls_msg_cert_status.obj: src/lib/tls/msg_cert_status.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_cert_status.cpp /Fo$@

build\obj\lib\tls_msg_cert_verify.obj: src/lib/tls/msg_cert_verify.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_cert_verify.cpp /Fo$@

build\obj\lib\tls_msg_certificate.obj: src/lib/tls/msg_certificate.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_certificate.cpp /Fo$@

build\obj\lib\tls_msg_client_hello.obj: src/lib/tls/msg_client_hello.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_client_hello.cpp /Fo$@

build\obj\lib\tls_msg_client_kex.obj: src/lib/tls/msg_client_kex.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_client_kex.cpp /Fo$@

build\obj\lib\tls_msg_finished.obj: src/lib/tls/msg_finished.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_finished.cpp /Fo$@

build\obj\lib\tls_msg_hello_verify.obj: src/lib/tls/msg_hello_verify.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_hello_verify.cpp /Fo$@

build\obj\lib\tls_msg_server_hello.obj: src/lib/tls/msg_server_hello.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_server_hello.cpp /Fo$@

build\obj\lib\tls_msg_server_kex.obj: src/lib/tls/msg_server_kex.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_server_kex.cpp /Fo$@

build\obj\lib\tls_msg_session_ticket.obj: src/lib/tls/msg_session_ticket.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/msg_session_ticket.cpp /Fo$@

build\obj\lib\tls_sessions_sql_tls_session_manager_sql.obj: src/lib/tls/sessions_sql/tls_session_manager_sql.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/sessions_sql/tls_session_manager_sql.cpp /Fo$@

build\obj\lib\tls_alert.obj: src/lib/tls/tls_alert.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_alert.cpp /Fo$@

build\obj\lib\tls_algos.obj: src/lib/tls/tls_algos.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_algos.cpp /Fo$@

build\obj\lib\tls_blocking.obj: src/lib/tls/tls_blocking.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_blocking.cpp /Fo$@

build\obj\lib\tls_callbacks.obj: src/lib/tls/tls_callbacks.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_callbacks.cpp /Fo$@

build\obj\lib\tls_cbc.obj: src/lib/tls/tls_cbc/tls_cbc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_cbc/tls_cbc.cpp /Fo$@

build\obj\lib\tls_channel.obj: src/lib/tls/tls_channel.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_channel.cpp /Fo$@

build\obj\lib\tls_ciphersuite.obj: src/lib/tls/tls_ciphersuite.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_ciphersuite.cpp /Fo$@

build\obj\lib\tls_client.obj: src/lib/tls/tls_client.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_client.cpp /Fo$@

build\obj\lib\tls_extensions.obj: src/lib/tls/tls_extensions.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_extensions.cpp /Fo$@

build\obj\lib\tls_handshake_hash.obj: src/lib/tls/tls_handshake_hash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_handshake_hash.cpp /Fo$@

build\obj\lib\tls_handshake_io.obj: src/lib/tls/tls_handshake_io.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_handshake_io.cpp /Fo$@

build\obj\lib\tls_handshake_state.obj: src/lib/tls/tls_handshake_state.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_handshake_state.cpp /Fo$@

build\obj\lib\tls_policy.obj: src/lib/tls/tls_policy.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_policy.cpp /Fo$@

build\obj\lib\tls_record.obj: src/lib/tls/tls_record.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_record.cpp /Fo$@

build\obj\lib\tls_server.obj: src/lib/tls/tls_server.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_server.cpp /Fo$@

build\obj\lib\tls_session.obj: src/lib/tls/tls_session.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_session.cpp /Fo$@

build\obj\lib\tls_session_key.obj: src/lib/tls/tls_session_key.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_session_key.cpp /Fo$@

build\obj\lib\tls_session_manager_memory.obj: src/lib/tls/tls_session_manager_memory.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_session_manager_memory.cpp /Fo$@

build\obj\lib\tls_suite_info.obj: src/lib/tls/tls_suite_info.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_suite_info.cpp /Fo$@

build\obj\lib\tls_text_policy.obj: src/lib/tls/tls_text_policy.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_text_policy.cpp /Fo$@

build\obj\lib\tls_version.obj: src/lib/tls/tls_version.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/tls/tls_version.cpp /Fo$@

build\obj\lib\utils_assert.obj: src/lib/utils/assert.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/assert.cpp /Fo$@

build\obj\lib\utils_calendar.obj: src/lib/utils/calendar.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/calendar.cpp /Fo$@

build\obj\lib\utils_charset.obj: src/lib/utils/charset.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/charset.cpp /Fo$@

build\obj\lib\utils_cpuid.obj: src/lib/utils/cpuid/cpuid.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/cpuid/cpuid.cpp /Fo$@

build\obj\lib\utils_cpuid_arm.obj: src/lib/utils/cpuid/cpuid_arm.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/cpuid/cpuid_arm.cpp /Fo$@

build\obj\lib\utils_cpuid_ppc.obj: src/lib/utils/cpuid/cpuid_ppc.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/cpuid/cpuid_ppc.cpp /Fo$@

build\obj\lib\utils_cpuid_x86.obj: src/lib/utils/cpuid/cpuid_x86.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/cpuid/cpuid_x86.cpp /Fo$@

build\obj\lib\utils_ct_utils.obj: src/lib/utils/ct_utils.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/ct_utils.cpp /Fo$@

build\obj\lib\utils_data_src.obj: src/lib/utils/data_src.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/data_src.cpp /Fo$@

build\obj\lib\utils_dyn_load.obj: src/lib/utils/dyn_load/dyn_load.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/dyn_load/dyn_load.cpp /Fo$@

build\obj\lib\utils_exceptn.obj: src/lib/utils/exceptn.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/exceptn.cpp /Fo$@

build\obj\lib\utils_filesystem.obj: src/lib/utils/filesystem.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/filesystem.cpp /Fo$@

build\obj\lib\utils_ghash.obj: src/lib/utils/ghash/ghash.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/ghash/ghash.cpp /Fo$@

build\obj\lib\utils_ghash_cpu.obj: src/lib/utils/ghash/ghash_cpu/ghash_cpu.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/ghash/ghash_cpu/ghash_cpu.cpp /Fo$@

build\obj\lib\utils_ghash_vperm.obj: src/lib/utils/ghash/ghash_vperm/ghash_vperm.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/ghash/ghash_vperm/ghash_vperm.cpp /Fo$@

build\obj\lib\utils_http_util.obj: src/lib/utils/http_util/http_util.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/http_util/http_util.cpp /Fo$@

build\obj\lib\utils_locking_allocator.obj: src/lib/utils/locking_allocator/locking_allocator.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/locking_allocator/locking_allocator.cpp /Fo$@

build\obj\lib\utils_mem_ops.obj: src/lib/utils/mem_ops.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/mem_ops.cpp /Fo$@

build\obj\lib\utils_mem_pool.obj: src/lib/utils/mem_pool/mem_pool.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/mem_pool/mem_pool.cpp /Fo$@

build\obj\lib\utils_os_utils.obj: src/lib/utils/os_utils.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/os_utils.cpp /Fo$@

build\obj\lib\utils_parsing.obj: src/lib/utils/parsing.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/parsing.cpp /Fo$@

build\obj\lib\utils_poly_dbl.obj: src/lib/utils/poly_dbl/poly_dbl.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/poly_dbl/poly_dbl.cpp /Fo$@

build\obj\lib\utils_read_cfg.obj: src/lib/utils/read_cfg.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/read_cfg.cpp /Fo$@

build\obj\lib\utils_read_kv.obj: src/lib/utils/read_kv.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/read_kv.cpp /Fo$@

build\obj\lib\utils_socket.obj: src/lib/utils/socket/socket.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/socket/socket.cpp /Fo$@

build\obj\lib\utils_socket_udp.obj: src/lib/utils/socket/socket_udp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/socket/socket_udp.cpp /Fo$@

build\obj\lib\utils_socket_uri.obj: src/lib/utils/socket/uri.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/socket/uri.cpp /Fo$@

build\obj\lib\utils_thread_utils_barrier.obj: src/lib/utils/thread_utils/barrier.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/thread_utils/barrier.cpp /Fo$@

build\obj\lib\utils_thread_utils_rwlock.obj: src/lib/utils/thread_utils/rwlock.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/thread_utils/rwlock.cpp /Fo$@

build\obj\lib\utils_thread_utils_semaphore.obj: src/lib/utils/thread_utils/semaphore.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/thread_utils/semaphore.cpp /Fo$@

build\obj\lib\utils_thread_utils_thread_pool.obj: src/lib/utils/thread_utils/thread_pool.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/thread_utils/thread_pool.cpp /Fo$@

build\obj\lib\utils_timer.obj: src/lib/utils/timer.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/timer.cpp /Fo$@

build\obj\lib\utils_uuid.obj: src/lib/utils/uuid/uuid.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/uuid/uuid.cpp /Fo$@

build\obj\lib\utils_version.obj: src/lib/utils/version.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/utils/version.cpp /Fo$@

build\obj\lib\x509_asn1_alt_name.obj: src/lib/x509/asn1_alt_name.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/asn1_alt_name.cpp /Fo$@

build\obj\lib\x509_cert_status.obj: src/lib/x509/cert_status.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/cert_status.cpp /Fo$@

build\obj\lib\x509_certstor.obj: src/lib/x509/certstor.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/certstor.cpp /Fo$@

build\obj\lib\x509_certstor_flatfile.obj: src/lib/x509/certstor_flatfile/certstor_flatfile.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/certstor_flatfile/certstor_flatfile.cpp /Fo$@

build\obj\lib\x509_certstor_sql.obj: src/lib/x509/certstor_sql/certstor_sql.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/certstor_sql/certstor_sql.cpp /Fo$@

build\obj\lib\x509_certstor_system.obj: src/lib/x509/certstor_system/certstor_system.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/certstor_system/certstor_system.cpp /Fo$@

build\obj\lib\x509_certstor_system_windows_certstor_windows.obj: src/lib/x509/certstor_system_windows/certstor_windows.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/certstor_system_windows/certstor_windows.cpp /Fo$@

build\obj\lib\x509_crl_ent.obj: src/lib/x509/crl_ent.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/crl_ent.cpp /Fo$@

build\obj\lib\x509_datastor.obj: src/lib/x509/datastor.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/datastor.cpp /Fo$@

build\obj\lib\x509_key_constraint.obj: src/lib/x509/key_constraint.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/key_constraint.cpp /Fo$@

build\obj\lib\x509_name_constraint.obj: src/lib/x509/name_constraint.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/name_constraint.cpp /Fo$@

build\obj\lib\x509_ocsp.obj: src/lib/x509/ocsp.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/ocsp.cpp /Fo$@

build\obj\lib\x509_ocsp_types.obj: src/lib/x509/ocsp_types.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/ocsp_types.cpp /Fo$@

build\obj\lib\x509_pkcs10.obj: src/lib/x509/pkcs10.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/pkcs10.cpp /Fo$@

build\obj\lib\x509_attribute.obj: src/lib/x509/x509_attribute.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_attribute.cpp /Fo$@

build\obj\lib\x509_ca.obj: src/lib/x509/x509_ca.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_ca.cpp /Fo$@

build\obj\lib\x509_crl.obj: src/lib/x509/x509_crl.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_crl.cpp /Fo$@

build\obj\lib\x509_dn.obj: src/lib/x509/x509_dn.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_dn.cpp /Fo$@

build\obj\lib\x509_dn_ub.obj: src/lib/x509/x509_dn_ub.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_dn_ub.cpp /Fo$@

build\obj\lib\x509_ext.obj: src/lib/x509/x509_ext.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_ext.cpp /Fo$@

build\obj\lib\x509_obj.obj: src/lib/x509/x509_obj.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509_obj.cpp /Fo$@

build\obj\lib\x509_x509cert.obj: src/lib/x509/x509cert.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509cert.cpp /Fo$@

build\obj\lib\x509_x509opt.obj: src/lib/x509/x509opt.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509opt.cpp /Fo$@

build\obj\lib\x509_x509path.obj: src/lib/x509/x509path.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509path.cpp /Fo$@

build\obj\lib\x509_x509self.obj: src/lib/x509/x509self.cpp
	$(CXX) $(LIB_FLAGS) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/lib/x509/x509self.cpp /Fo$@



build\obj\cli\argon2.obj: src/cli/argon2.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/argon2.cpp /Fo$@

build\obj\cli\asn1.obj: src/cli/asn1.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/asn1.cpp /Fo$@

build\obj\cli\bcrypt.obj: src/cli/bcrypt.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/bcrypt.cpp /Fo$@

build\obj\cli\cc_enc.obj: src/cli/cc_enc.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/cc_enc.cpp /Fo$@

build\obj\cli\cli.obj: src/cli/cli.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/cli.cpp /Fo$@

build\obj\cli\cli_rng.obj: src/cli/cli_rng.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/cli_rng.cpp /Fo$@

build\obj\cli\codec.obj: src/cli/codec.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/codec.cpp /Fo$@

build\obj\cli\compress.obj: src/cli/compress.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/compress.cpp /Fo$@

build\obj\cli\encryption.obj: src/cli/encryption.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/encryption.cpp /Fo$@

build\obj\cli\entropy.obj: src/cli/entropy.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/entropy.cpp /Fo$@

build\obj\cli\hash.obj: src/cli/hash.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/hash.cpp /Fo$@

build\obj\cli\hmac.obj: src/cli/hmac.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/hmac.cpp /Fo$@

build\obj\cli\main.obj: src/cli/main.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/main.cpp /Fo$@

build\obj\cli\math.obj: src/cli/math.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/math.cpp /Fo$@

build\obj\cli\pbkdf.obj: src/cli/pbkdf.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/pbkdf.cpp /Fo$@

build\obj\cli\pk_crypt.obj: src/cli/pk_crypt.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/pk_crypt.cpp /Fo$@

build\obj\cli\psk.obj: src/cli/psk.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/psk.cpp /Fo$@

build\obj\cli\pubkey.obj: src/cli/pubkey.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/pubkey.cpp /Fo$@

build\obj\cli\roughtime.obj: src/cli/roughtime.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/roughtime.cpp /Fo$@

build\obj\cli\sandbox.obj: src/cli/sandbox.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/sandbox.cpp /Fo$@

build\obj\cli\speed.obj: src/cli/speed.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/speed.cpp /Fo$@

build\obj\cli\timing_tests.obj: src/cli/timing_tests.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/timing_tests.cpp /Fo$@

build\obj\cli\tls_client.obj: src/cli/tls_client.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/tls_client.cpp /Fo$@

build\obj\cli\tls_http_server.obj: src/cli/tls_http_server.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/tls_http_server.cpp /Fo$@

build\obj\cli\tls_proxy.obj: src/cli/tls_proxy.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/tls_proxy.cpp /Fo$@

build\obj\cli\tls_server.obj: src/cli/tls_server.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/tls_server.cpp /Fo$@

build\obj\cli\tls_utils.obj: src/cli/tls_utils.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/tls_utils.cpp /Fo$@

build\obj\cli\tss.obj: src/cli/tss.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/tss.cpp /Fo$@

build\obj\cli\utils.obj: src/cli/utils.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/utils.cpp /Fo$@

build\obj\cli\x509.obj: src/cli/x509.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/cli/x509.cpp /Fo$@



build\obj\test\main.obj: src/tests/main.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/main.cpp /Fo$@

build\obj\test\test_aead.obj: src/tests/test_aead.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_aead.cpp /Fo$@

build\obj\test\test_asn1.obj: src/tests/test_asn1.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_asn1.cpp /Fo$@

build\obj\test\test_bigint.obj: src/tests/test_bigint.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_bigint.cpp /Fo$@

build\obj\test\test_block.obj: src/tests/test_block.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_block.cpp /Fo$@

build\obj\test\test_blowfish.obj: src/tests/test_blowfish.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_blowfish.cpp /Fo$@

build\obj\test\test_c25519.obj: src/tests/test_c25519.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_c25519.cpp /Fo$@

build\obj\test\test_certstor.obj: src/tests/test_certstor.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_certstor.cpp /Fo$@

build\obj\test\test_certstor_flatfile.obj: src/tests/test_certstor_flatfile.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_certstor_flatfile.cpp /Fo$@

build\obj\test\test_certstor_system.obj: src/tests/test_certstor_system.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_certstor_system.cpp /Fo$@

build\obj\test\test_certstor_utils.obj: src/tests/test_certstor_utils.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_certstor_utils.cpp /Fo$@

build\obj\test\test_clang_bug.obj: src/tests/test_clang_bug.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_clang_bug.cpp /Fo$@

build\obj\test\test_compression.obj: src/tests/test_compression.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_compression.cpp /Fo$@

build\obj\test\test_cryptobox.obj: src/tests/test_cryptobox.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_cryptobox.cpp /Fo$@

build\obj\test\test_datastore.obj: src/tests/test_datastore.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_datastore.cpp /Fo$@

build\obj\test\test_dh.obj: src/tests/test_dh.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_dh.cpp /Fo$@

build\obj\test\test_dl_group.obj: src/tests/test_dl_group.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_dl_group.cpp /Fo$@

build\obj\test\test_dlies.obj: src/tests/test_dlies.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_dlies.cpp /Fo$@

build\obj\test\test_dsa.obj: src/tests/test_dsa.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_dsa.cpp /Fo$@

build\obj\test\test_ecc_pointmul.obj: src/tests/test_ecc_pointmul.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ecc_pointmul.cpp /Fo$@

build\obj\test\test_ecdh.obj: src/tests/test_ecdh.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ecdh.cpp /Fo$@

build\obj\test\test_ecdsa.obj: src/tests/test_ecdsa.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ecdsa.cpp /Fo$@

build\obj\test\test_ecgdsa.obj: src/tests/test_ecgdsa.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ecgdsa.cpp /Fo$@

build\obj\test\test_ecies.obj: src/tests/test_ecies.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ecies.cpp /Fo$@

build\obj\test\test_eckcdsa.obj: src/tests/test_eckcdsa.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_eckcdsa.cpp /Fo$@

build\obj\test\test_ed25519.obj: src/tests/test_ed25519.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ed25519.cpp /Fo$@

build\obj\test\test_elg.obj: src/tests/test_elg.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_elg.cpp /Fo$@

build\obj\test\test_entropy.obj: src/tests/test_entropy.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_entropy.cpp /Fo$@

build\obj\test\test_ffi.obj: src/tests/test_ffi.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ffi.cpp /Fo$@

build\obj\test\test_filters.obj: src/tests/test_filters.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_filters.cpp /Fo$@

build\obj\test\test_fpe.obj: src/tests/test_fpe.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_fpe.cpp /Fo$@

build\obj\test\test_gf2m.obj: src/tests/test_gf2m.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_gf2m.cpp /Fo$@

build\obj\test\test_gost_3410.obj: src/tests/test_gost_3410.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_gost_3410.cpp /Fo$@

build\obj\test\test_hash.obj: src/tests/test_hash.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_hash.cpp /Fo$@

build\obj\test\test_hash_id.obj: src/tests/test_hash_id.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_hash_id.cpp /Fo$@

build\obj\test\test_kdf.obj: src/tests/test_kdf.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_kdf.cpp /Fo$@

build\obj\test\test_keywrap.obj: src/tests/test_keywrap.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_keywrap.cpp /Fo$@

build\obj\test\test_mac.obj: src/tests/test_mac.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_mac.cpp /Fo$@

build\obj\test\test_mceliece.obj: src/tests/test_mceliece.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_mceliece.cpp /Fo$@

build\obj\test\test_modes.obj: src/tests/test_modes.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_modes.cpp /Fo$@

build\obj\test\test_mp.obj: src/tests/test_mp.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_mp.cpp /Fo$@

build\obj\test\test_name_constraint.obj: src/tests/test_name_constraint.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_name_constraint.cpp /Fo$@

build\obj\test\test_newhope.obj: src/tests/test_newhope.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_newhope.cpp /Fo$@

build\obj\test\test_ocb.obj: src/tests/test_ocb.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ocb.cpp /Fo$@

build\obj\test\test_ocsp.obj: src/tests/test_ocsp.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_ocsp.cpp /Fo$@

build\obj\test\test_octetstring.obj: src/tests/test_octetstring.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_octetstring.cpp /Fo$@

build\obj\test\test_oid.obj: src/tests/test_oid.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_oid.cpp /Fo$@

build\obj\test\test_os_utils.obj: src/tests/test_os_utils.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_os_utils.cpp /Fo$@

build\obj\test\test_otp.obj: src/tests/test_otp.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_otp.cpp /Fo$@

build\obj\test\test_package_transform.obj: src/tests/test_package_transform.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_package_transform.cpp /Fo$@

build\obj\test\test_pad.obj: src/tests/test_pad.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pad.cpp /Fo$@

build\obj\test\test_passhash.obj: src/tests/test_passhash.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_passhash.cpp /Fo$@

build\obj\test\test_pbkdf.obj: src/tests/test_pbkdf.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pbkdf.cpp /Fo$@

build\obj\test\test_pem.obj: src/tests/test_pem.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pem.cpp /Fo$@

build\obj\test\test_pk_pad.obj: src/tests/test_pk_pad.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pk_pad.cpp /Fo$@

build\obj\test\test_pkcs11_high_level.obj: src/tests/test_pkcs11_high_level.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pkcs11_high_level.cpp /Fo$@

build\obj\test\test_pkcs11_low_level.obj: src/tests/test_pkcs11_low_level.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pkcs11_low_level.cpp /Fo$@

build\obj\test\test_psk_db.obj: src/tests/test_psk_db.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_psk_db.cpp /Fo$@

build\obj\test\test_pubkey.obj: src/tests/test_pubkey.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_pubkey.cpp /Fo$@

build\obj\test\test_rfc6979.obj: src/tests/test_rfc6979.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_rfc6979.cpp /Fo$@

build\obj\test\test_rng.obj: src/tests/test_rng.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_rng.cpp /Fo$@

build\obj\test\test_rng_kat.obj: src/tests/test_rng_kat.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_rng_kat.cpp /Fo$@

build\obj\test\test_roughtime.obj: src/tests/test_roughtime.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_roughtime.cpp /Fo$@

build\obj\test\test_rsa.obj: src/tests/test_rsa.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_rsa.cpp /Fo$@

build\obj\test\test_runner.obj: src/tests/test_runner.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_runner.cpp /Fo$@

build\obj\test\test_simd.obj: src/tests/test_simd.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_simd.cpp /Fo$@

build\obj\test\test_siv.obj: src/tests/test_siv.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_siv.cpp /Fo$@

build\obj\test\test_sm2.obj: src/tests/test_sm2.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_sm2.cpp /Fo$@

build\obj\test\test_sodium.obj: src/tests/test_sodium.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_sodium.cpp /Fo$@

build\obj\test\test_srp6.obj: src/tests/test_srp6.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_srp6.cpp /Fo$@

build\obj\test\test_stream.obj: src/tests/test_stream.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_stream.cpp /Fo$@

build\obj\test\test_tests.obj: src/tests/test_tests.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_tests.cpp /Fo$@

build\obj\test\test_thread_utils.obj: src/tests/test_thread_utils.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_thread_utils.cpp /Fo$@

build\obj\test\test_tls.obj: src/tests/test_tls.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_tls.cpp /Fo$@

build\obj\test\test_tls_messages.obj: src/tests/test_tls_messages.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_tls_messages.cpp /Fo$@

build\obj\test\test_tls_stream_integration.obj: src/tests/test_tls_stream_integration.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_tls_stream_integration.cpp /Fo$@

build\obj\test\test_tpm.obj: src/tests/test_tpm.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_tpm.cpp /Fo$@

build\obj\test\test_tss.obj: src/tests/test_tss.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_tss.cpp /Fo$@

build\obj\test\test_uri.obj: src/tests/test_uri.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_uri.cpp /Fo$@

build\obj\test\test_utils.obj: src/tests/test_utils.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_utils.cpp /Fo$@

build\obj\test\test_workfactor.obj: src/tests/test_workfactor.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_workfactor.cpp /Fo$@

build\obj\test\test_x509_dn.obj: src/tests/test_x509_dn.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_x509_dn.cpp /Fo$@

build\obj\test\test_x509_path.obj: src/tests/test_x509_path.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_x509_path.cpp /Fo$@

build\obj\test\test_xmss.obj: src/tests/test_xmss.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/test_xmss.cpp /Fo$@

build\obj\test\tests.obj: src/tests/tests.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/tests.cpp /Fo$@

build\obj\test\unit_asio_stream.obj: src/tests/unit_asio_stream.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_asio_stream.cpp /Fo$@

build\obj\test\unit_ecc.obj: src/tests/unit_ecc.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_ecc.cpp /Fo$@

build\obj\test\unit_ecdh.obj: src/tests/unit_ecdh.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_ecdh.cpp /Fo$@

build\obj\test\unit_ecdsa.obj: src/tests/unit_ecdsa.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_ecdsa.cpp /Fo$@

build\obj\test\unit_tls.obj: src/tests/unit_tls.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_tls.cpp /Fo$@

build\obj\test\unit_tls_policy.obj: src/tests/unit_tls_policy.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_tls_policy.cpp /Fo$@

build\obj\test\unit_x509.obj: src/tests/unit_x509.cpp
	$(CXX) $(BUILD_FLAGS)  /Ibuild\include /Ibuild\include\external /nologo /c src/tests/unit_x509.cpp /Fo$@





