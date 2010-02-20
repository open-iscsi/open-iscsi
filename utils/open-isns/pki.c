/*
 * PKI related functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fcntl.h>
#include "isns.h"
#include "security.h"
#include "util.h"
#include "config.h"

#ifdef WITH_SECURITY

/* versions prior to 9.6.8 didn't seem to have these */
#if OPADDRCONFIGENSSL_VERSION_NUMBER < 0x00906080L
# define EVP_MD_CTX_init(c)	do { } while (0)
# define EVP_MD_CTX_cleanup(c)	do { } while (0)
#endif
#if OPADDRCONFIGENSSL_VERSION_NUMBER < 0x00906070L
# define i2d_DSA_PUBKEY		i2d_DSA_PUBKEY_backwards

static int	i2d_DSA_PUBKEY_backwards(DSA *, unsigned char **);
#endif

static int	isns_openssl_init = 0;

static int	isns_dsasig_verify(isns_security_t *ctx,
				isns_principal_t *peer,
				buf_t *pdu,
				const struct isns_authblk *);
static int	isns_dsasig_sign(isns_security_t *ctx,
				isns_principal_t *peer,
				buf_t *pdu,
				struct isns_authblk *);
static EVP_PKEY *isns_dsasig_load_private_pem(isns_security_t *ctx,
				const char *filename);
static EVP_PKEY *isns_dsasig_load_public_pem(isns_security_t *ctx,
				const char *filename);
static DSA *	isns_dsa_load_params(const char *);


/*
 * Create a DSA security context
 */
isns_security_t *
isns_create_dsa_context(void)
{
	isns_security_t	*ctx;

	if (!isns_openssl_init) {
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_ciphers();
		OpenSSL_add_all_digests();
		isns_openssl_init = 1;
	}

	ctx = isns_calloc(1, sizeof(*ctx));

	ctx->is_name = "DSA";
	ctx->is_type = ISNS_AUTH_TYPE_SHA1_DSA;
	ctx->is_replay_window = isns_config.ic_auth.replay_window;
	ctx->is_timestamp_jitter = isns_config.ic_auth.timestamp_jitter;

	ctx->is_verify = isns_dsasig_verify;
	ctx->is_sign = isns_dsasig_sign;
	ctx->is_load_private = isns_dsasig_load_private_pem;
	ctx->is_load_public = isns_dsasig_load_public_pem;

	isns_debug_auth("Created DSA authentication context\n");
	return ctx;
}

/*
 * DSA signature generation and verification
 */
static void
isns_message_digest(EVP_MD_CTX *md, const buf_t *pdu,
		const struct isns_authblk *blk)
{
	uint64_t	stamp;

	EVP_DigestUpdate(md, buf_head(pdu), buf_avail(pdu));

	/* The RFC doesn't say which pieces of the
	 * message should be hashed.
	 * We make an educated guess.
	 */
	stamp = htonll(blk->iab_timestamp);
	EVP_DigestUpdate(md, &stamp, sizeof(stamp));
}

static void
isns_dsasig_report_errors(const char *msg, isns_print_fn_t *fn)
{
	unsigned long	code;

	fn("%s - OpenSSL errors follow:\n", msg);
	while ((code = ERR_get_error()) != 0)
		fn("> %s: %s\n",
			ERR_func_error_string(code),
			ERR_reason_error_string(code));
}

int
isns_dsasig_sign(isns_security_t *ctx,
			isns_principal_t *peer,
			buf_t *pdu,
			struct isns_authblk *blk)
{
	static unsigned char signature[1024];
	unsigned int	sig_len = sizeof(signature);
	EVP_MD_CTX	md_ctx;
	EVP_PKEY	*pkey;
	int		err;

	if ((pkey = peer->is_key) == NULL)
		return 0;

	if (pkey->type != EVP_PKEY_DSA) {
		isns_debug_message(
			"Incompatible public key (spi=%s)\n",
			peer->is_name);
		return 0;
	}
	if (EVP_PKEY_size(pkey) > sizeof(signature)) {
		isns_error("isns_dsasig_sign: signature buffer too small\n");
		return 0;
	}
	if (pkey->pkey.dsa->priv_key == NULL) {
		isns_error("isns_dsasig_sign: oops, seems to be a public key\n");
		return 0;
	}

	isns_debug_auth("Signing messages with spi=%s, DSA/%u\n",
			peer->is_name, EVP_PKEY_bits(pkey));

	EVP_MD_CTX_init(&md_ctx);
	EVP_SignInit(&md_ctx, EVP_dss1());
	isns_message_digest(&md_ctx, pdu, blk);
	err = EVP_SignFinal(&md_ctx,
				signature, &sig_len,
				pkey);
	EVP_MD_CTX_cleanup(&md_ctx);

	if (err == 0) {
		isns_dsasig_report_errors("EVP_SignFinal failed", isns_error);
		return 0;
	}

	blk->iab_sig = signature;
	blk->iab_sig_len = sig_len;
	return 1;
}

int
isns_dsasig_verify(isns_security_t *ctx,
			isns_principal_t *peer,
			buf_t *pdu,
			const struct isns_authblk *blk)
{
	EVP_MD_CTX	md_ctx;
	EVP_PKEY	*pkey;
	int		err;

	if ((pkey = peer->is_key) == NULL)
		return 0;

	if (pkey->type != EVP_PKEY_DSA) {
		isns_debug_message(
			"Incompatible public key (spi=%s)\n",
			peer->is_name);
		return 0;
	}

	EVP_MD_CTX_init(&md_ctx);
	EVP_VerifyInit(&md_ctx, EVP_dss1());
	isns_message_digest(&md_ctx, pdu, blk);
	err = EVP_VerifyFinal(&md_ctx,
			blk->iab_sig, blk->iab_sig_len,
			pkey);
	EVP_MD_CTX_cleanup(&md_ctx);
	
	if (err == 0) {
		isns_debug_auth("*** Incorrect signature ***\n");
		return 0;
	}
	if (err < 0) {
		isns_dsasig_report_errors("EVP_VerifyFinal failed", isns_error);
		return 0;
	}

	isns_debug_message("Good signature from %s\n",
			peer->is_name?: "<server>");
	return 1;
}

EVP_PKEY *
isns_dsasig_load_private_pem(isns_security_t *ctx, const char *filename)
{
	EVP_PKEY	*pkey;
	FILE		*fp;

	if (!(fp = fopen(filename, "r"))) {
		isns_error("Unable to open DSA keyfile %s: %m\n",
				filename);
		return 0;
	}

	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey;
}

EVP_PKEY *
isns_dsasig_load_public_pem(isns_security_t *ctx, const char *filename)
{
	EVP_PKEY	*pkey;
	FILE		*fp;

	if (!(fp = fopen(filename, "r"))) {
		isns_error("Unable to open DSA keyfile %s: %m\n",
				filename);
		return 0;
	}

	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	if (pkey == NULL) {
		isns_dsasig_report_errors("Error loading DSA public key",
				isns_error);
	}

	fclose(fp);
	return pkey;
}

EVP_PKEY *
isns_dsa_decode_public(const void *ptr, size_t len)
{
	const unsigned char *der = ptr;
	EVP_PKEY *evp;
	DSA	*dsa;

	/* Assigning ptr to a temporary variable avoids a silly
	 * compiled warning about type-punning. */
	dsa = d2i_DSA_PUBKEY(NULL, &der, len);
	if (dsa == NULL)
		return NULL;

	evp = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(evp, dsa);
	return evp;
}

int
isns_dsa_encode_public(EVP_PKEY *pkey, void **ptr, size_t *len)
{
	int	bytes;

	*ptr = NULL;
	bytes = i2d_DSA_PUBKEY(pkey->pkey.dsa, (unsigned char **) ptr);
	if (bytes < 0)
		return 0;

	*len = bytes;
	return 1;
}

EVP_PKEY *
isns_dsa_load_public(const char *name)
{
	return isns_dsasig_load_public_pem(NULL, name);
}

int
isns_dsa_store_private(const char *name, EVP_PKEY *key)
{
	FILE	*fp;
	int	rv, fd;

	if ((fd = open(name, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
		isns_error("Cannot save DSA key to %s: %m\n", name);
		return 0;
	}

	if (!(fp = fdopen(fd, "w"))) {
		isns_error("fdopen(%s): %m\n", name);
		close(fd);
		return 0;
	}

	rv = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, 0, NULL);
	fclose(fp);

	if (rv == 0)
		isns_dsasig_report_errors("Failed to store private key",
				isns_error);

	return rv;
}

int
isns_dsa_store_public(const char *name, EVP_PKEY *key)
{
	FILE	*fp;
	int	rv;

	if (!(fp = fopen(name, "w"))) {
		isns_error("Unable to open %s: %m\n", name);
		return 0;
	}

	rv = PEM_write_PUBKEY(fp, key);
	fclose(fp);

	if (rv == 0)
		isns_dsasig_report_errors("Failed to store public key",
				isns_error);

	return rv;
}


/*
 * DSA key generation
 */
EVP_PKEY *
isns_dsa_generate_key(void)
{
	EVP_PKEY *pkey;
	DSA	*dsa = NULL;

	if (!(dsa = isns_dsa_load_params(isns_config.ic_dsa.param_file)))
		goto failed;

	if (!DSA_generate_key(dsa)) {
		isns_dsasig_report_errors("Failed to generate DSA key",
				isns_error);
		goto failed;
	}

	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(pkey, dsa);
	return pkey;

failed:
	if (dsa)
		DSA_free(dsa);
	return NULL;
}

DSA *
isns_dsa_load_params(const char *filename)
{
	FILE	*fp;
	DSA	*dsa;

	if (!filename) {
		isns_error("Cannot generate key - no DSA parameter file\n");
		return NULL;
	}
	if (!(fp = fopen(filename, "r"))) {
		isns_error("Unable to open %s: %m\n", filename);
		return NULL;
	}

	dsa = PEM_read_DSAparams(fp, NULL, NULL, NULL);
	fclose(fp);

	if (dsa == NULL) {
		isns_dsasig_report_errors("Error loading DSA parameters",
				isns_error);
	}

	return dsa;
}

static void
isns_dsa_param_gen_callback(int stage, int index, void *dummy)
{
	if (stage == 0)
		write(1, "+", 1);
	else if (stage == 1)
		write(1, ".", 1);
	else if (stage == 2)
		write(1, "/", 1);
}

int
isns_dsa_init_params(const char *filename)
{
	FILE	*fp;
	DSA	*dsa;

	if (access(filename, R_OK) == 0)
		return 1;

	isns_mkdir_recursive(isns_dirname(filename));
	if (!(fp = fopen(filename, "w"))) {
		isns_error("Unable to open %s: %m\n", filename);
		return 0;
	}

	isns_notice("Generating DSA parameters; this may take a while\n");
	dsa = DSA_generate_parameters(1024, NULL, 0,
			NULL, NULL, isns_dsa_param_gen_callback, NULL);
	write(1, "\n", 1);

	if (dsa == NULL) {
		isns_dsasig_report_errors("Error generating DSA parameters",
				isns_error);
		fclose(fp);
		return 0;
	}

	if (!PEM_write_DSAparams(fp, dsa)) {
		isns_dsasig_report_errors("Error writing DSA parameters",
				isns_error);
		DSA_free(dsa);
		fclose(fp);
		return 0;
	}
	DSA_free(dsa);
	fclose(fp);
	return 1;
}

/*
 * Make sure the authentication key is present.
 */
int
isns_dsa_init_key(const char *filename)
{
	char	pubkey_path[1024];
	EVP_PKEY *pkey;

	isns_mkdir_recursive(isns_dirname(filename));
	snprintf(pubkey_path, sizeof(pubkey_path),
				"%s.pub", filename);
	if (access(filename, R_OK) == 0
	 && access(pubkey_path, R_OK) == 0)
		return 1;

	if (!(pkey = isns_dsa_generate_key())) {
		isns_error("Failed to generate AuthKey\n");
		return 0;
	}

	if (!isns_dsa_store_private(filename, pkey)) {
		isns_error("Unable to write private key to %s\n", filename);
		return 0;
	}
	isns_notice("Stored private key in %s\n", filename);

	if (!isns_dsa_store_public(pubkey_path, pkey)) {
		isns_error("Unable to write public key to %s\n", pubkey_path);
		return 0;
	}
	isns_notice("Stored private key in %s\n", pubkey_path);

	return 1;
}

/*
 * Simple keystore - this is a flat directory, with
 * public key files using the SPI as their name.
 */
typedef struct isns_simple_keystore isns_simple_keystore_t;
struct isns_simple_keystore {
	isns_keystore_t	sc_base;
	char *		sc_dirpath;
};

/*
 * Load a DSA key from the cert store
 * In fact, this will load RSA keys as well.
 */
static EVP_PKEY *
__isns_simple_keystore_find(isns_keystore_t *store_base,
		const char *name, size_t namelen)
{
	isns_simple_keystore_t *store = (isns_simple_keystore_t *) store_base;
	char		pathname[PATH_MAX];

	/* Refuse to open key files with names
	 * that refer to parent directories */
	if (memchr(name, '/', namelen) || name[0] == '.')
		return NULL;

	snprintf(pathname, sizeof(pathname),
			"%s/%.*s", store->sc_dirpath,
			(int) namelen, name);
	if (access(pathname, R_OK) < 0)
		return NULL;
	return isns_dsasig_load_public_pem(NULL, pathname);
}

isns_keystore_t *
isns_create_simple_keystore(const char *dirname)
{
	isns_simple_keystore_t *store;

	store = isns_calloc(1, sizeof(*store));
	store->sc_base.ic_name = "simple key store";
	store->sc_base.ic_find = __isns_simple_keystore_find;
	store->sc_dirpath = isns_strdup(dirname);

	return (isns_keystore_t *) store;
}

#if OPADDRCONFIGENSSL_VERSION_NUMBER < 0x00906070L
#undef i2d_DSA_PUBKEY

int
i2d_DSA_PUBKEY_backwards(DSA *dsa, unsigned char **ptr)
{
	unsigned char *buf;
	int len;

	len = i2d_DSA_PUBKEY(dsa, NULL);
	if (len < 0)
		return 0;

	*ptr = buf = OPENSSL_malloc(len);
	return i2d_DSA_PUBKEY(dsa, &buf);
}
#endif

#endif /* WITH_SECURITY */
