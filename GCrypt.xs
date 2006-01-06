/*
 ===========================================================================
 Crypt::GCrypt

 Perl interface to the GNU Cryptographic library
 
 Author: Alessandro Ranellucci <aar@cpan.org>
 Copyright (c) 2005.
 
 Use this software AT YOUR OWN RISK.
 ===========================================================================
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <gcrypt.h>
#include <string.h>

static const char my_name[] = "Crypt::GCrypt";
static const char author[] = "Alessandro Ranellucci <aar@cpan.org>";

enum cg_type
{
	CG_TYPE_CIPHER,
	CG_TYPE_ASYMM
};
enum cg_action
{
	CG_ACTION_NONE,
	CG_ACTION_ENCRYPT,
	CG_ACTION_DECRYPT
};
enum cg_padding
{
	CG_PADDING_STANDARD,
	CG_PADDING_NULL,
	CG_PADDING_SPACE
};

struct Crypt_GCrypt_s {
	int type;
	int action;
	gcry_cipher_hd_t h;
	gcry_ac_handle_t h_ac;
	gcry_ac_key_t key_ac;
	gcry_error_t err;
	int mode;
	int padding;
	unsigned int blklen, keylen;
	unsigned char *buffer;
	int buflen;
};
typedef struct Crypt_GCrypt_s *Crypt_GCrypt;

MODULE = Crypt::GCrypt		PACKAGE = Crypt::GCrypt	PREFIX = cg_

Crypt_GCrypt
cg_new(...)
	PROTOTYPE: @
	INIT:
		char *s, *algo_s, *mode_s;
		int i, algo, mode;
		unsigned int c_flags, ac_flags;
		gcry_ac_id_t ac_algo;
		bool have_mode;
	CODE:
		New(0, RETVAL, 1, struct Crypt_GCrypt_s);
		s = SvPV_nolen(ST(0));
		if (strcmp(s, "Crypt::GCrypt") == 0) {
			i = 1;
		} else {
			i = 0;
		}
		if ((items-i % 2) == 1)
			croak("Wrong number of arguments for Crypt::GCrypt->new()");
			
		/* Default values: */
		RETVAL->type = -1;
		RETVAL->padding = CG_PADDING_STANDARD;
		RETVAL->action = CG_ACTION_NONE;
		c_flags = 0;
		ac_flags = 0;
		have_mode = 0;
		
		/* Let's get parameters: */
		while (i < items) {
			s = SvPV_nolen(ST(i));
			if (strcmp(s, "type") == 0) {
				s = SvPV_nolen(ST(i+1));
				if (strcmp(s, "cipher") == 0)
					RETVAL->type = CG_TYPE_CIPHER;
				if (strcmp(s, "asymm") == 0)
					RETVAL->type = CG_TYPE_ASYMM;
			}
			if (strcmp(s, "algorithm") == 0) {
				algo_s = SvPV_nolen(ST(i+1));
			}
			if (strcmp(s, "mode") == 0) {
				mode_s = SvPV_nolen(ST(i+1));
				have_mode = 1;
			}
			if (strcmp(s, "padding") == 0) {
				s = SvPV_nolen(ST(i+1));
				if (strcmp(s, "standard") == 0)
					RETVAL->padding = CG_PADDING_STANDARD;
				if (strcmp(s, "null") == 0)
					RETVAL->padding = CG_PADDING_NULL;
			}
			if (strcmp(s, "secure") == 0) {
				if (SvTRUE(ST(i+1))) c_flags |= GCRY_CIPHER_SECURE;
			}
			if (strcmp(s, "enable_sync") == 0) {
				if (SvTRUE(ST(i+1))) c_flags |= GCRY_CIPHER_ENABLE_SYNC;
			}
			i = i + 2;
		}
		if (RETVAL->type == -1)
			croak("No type specified for Crypt::GCrypt->new()");
		if (!algo_s)
			croak("No algorithm specified for Crypt::GCrypt->new()");

		if (RETVAL->type == CG_TYPE_CIPHER) {
			/* Checking algorithm */
			if (!(algo = gcry_cipher_map_name(algo_s)))
				croak("Unknown algorithm %s", algo_s);
			RETVAL->blklen = gcry_cipher_get_algo_blklen(algo);
			RETVAL->keylen  = gcry_cipher_get_algo_keylen(algo);
			
			/* Checking mode */
			if (have_mode) {
				switch (mode_s[0]) {
					case 'e':
						if (strcmp(mode_s+1, "cb") == 0)
							RETVAL->mode = GCRY_CIPHER_MODE_ECB;
						break;
					case 'c':
						if (strcmp(mode_s+1, "fb") == 0)
							RETVAL->mode = GCRY_CIPHER_MODE_CFB;
						else if (strcmp(mode_s+1, "bc") == 0)
							RETVAL->mode = GCRY_CIPHER_MODE_CBC;
						break;
					case 's':
						if (strcmp(mode_s+1, "tream") == 0)
							RETVAL->mode = GCRY_CIPHER_MODE_STREAM;
						break;
					case 'o':
						if (strcmp(mode_s+1, "fb") == 0)
							RETVAL->mode = GCRY_CIPHER_MODE_OFB;
						break;
				}
			} else {
				RETVAL->mode = RETVAL->blklen > 1 ? GCRY_CIPHER_MODE_CBC
					    : GCRY_CIPHER_MODE_STREAM;
			}
			if (!RETVAL->mode)
				croak("Unknown mode %s", mode_s);
			
			/* Init cipher */
			RETVAL->err = gcry_cipher_open(&RETVAL->h, algo, RETVAL->mode, c_flags);
			if (RETVAL->h == NULL) XSRETURN_UNDEF;
		}
		if (RETVAL->type == CG_TYPE_ASYMM) {
		
			croak("Asymmetric cryptography is not yet supported by Crypt::GCrypt");
			
			RETVAL->err = gcry_ac_name_to_id(algo_s, &ac_algo);
			if (RETVAL->err)
				croak("Unknown algorithm %s", algo_s);
			
			/* Init ac */
			RETVAL->err = gcry_ac_open(&RETVAL->h_ac, ac_algo, ac_flags);
			if (RETVAL->h_ac == NULL) XSRETURN_UNDEF;
		}
		

	OUTPUT:
		RETVAL

SV *
cg_encrypt(gcr, in)
	Crypt_GCrypt gcr;
	SV *in;
    PREINIT:
		unsigned char *ibuf, *curbuf, *obuf;
		size_t len, ilen, buflen;
    CODE:
    	if (gcr->action != CG_ACTION_ENCRYPT)
    		croak("start('encrypting') was not called");
    	
		ibuf = SvPV(in, ilen);
		
		/* Get total buffer+ibuf length */
		Newz(0, curbuf, ilen + gcr->buflen, unsigned char);
		memcpy(curbuf, gcr->buffer, gcr->buflen);
		memcpy(curbuf+gcr->buflen, ibuf, ilen);
		
		if ((len = (ilen+gcr->buflen) % gcr->blklen) == 0) {
			len = ilen+gcr->buflen;
			gcr->buffer[0] = '\0';
			gcr->buflen = 0;
		} else {
			unsigned char *tmpbuf;
			len = (ilen+gcr->buflen) - len;   /* len contiene i byte da scrivere effettivemente */
			
			Newz(0, tmpbuf, len, unsigned char);
			memcpy(tmpbuf, curbuf, len);
			memcpy(gcr->buffer, curbuf+len, (ilen+gcr->buflen)-len);
			gcr->buflen = (ilen+gcr->buflen)-len;
			Safefree(curbuf);
			curbuf = tmpbuf;
		}

		/* Encrypt data */
		New(0, obuf, len, unsigned char);
		if (len > 0) {
			if ((gcr->err = gcry_cipher_encrypt(gcr->h, obuf, len, curbuf, len)) != 0)
				croak("encrypt: %s", gcry_strerror(gcr->err));
		}
		RETVAL = newSVpvn(obuf, len);
		Safefree(curbuf);
		Safefree(obuf);
    OUTPUT:
		RETVAL

SV *
cg_finish(gcr)
	Crypt_GCrypt gcr;
    PREINIT:
		unsigned char *obuf;
		size_t rlen;
    CODE:
    	if (gcr->action != CG_ACTION_ENCRYPT)
    		croak("start('encrypting') was not called");

    	if (gcr->buflen < gcr->blklen) {
    		rlen = gcr->blklen - gcr->buflen;
    		unsigned char *tmpbuf;
    		Newz(0, tmpbuf, gcr->buflen+rlen, unsigned char);
    		memcpy(tmpbuf, gcr->buffer, gcr->buflen);
    		switch (gcr->padding) {
    			case CG_PADDING_STANDARD:
	    			memset(tmpbuf + gcr->buflen, rlen, rlen);
	    			break;
    			case CG_PADDING_NULL:
	    			memset(tmpbuf + gcr->buflen, 0, rlen);
	    			break;
    			case CG_PADDING_SPACE:
	    			memset(tmpbuf + gcr->buflen, '\32', rlen);
	    			break;
	    	}
	    	Safefree(gcr->buffer);
    		gcr->buffer = tmpbuf;
    	} else {
    		if (gcr->padding == CG_PADDING_NULL && gcr->blklen == 8) {
    			unsigned char *tmpbuf;
    			Newz(0, tmpbuf, gcr->buflen+8, unsigned char);
    			memcpy(tmpbuf, gcr->buffer, gcr->buflen);
    			memset(tmpbuf + gcr->buflen, 0, 8);
    			Safefree(gcr->buffer);
    			gcr->buffer = tmpbuf;
    		}
    	}
    	Newz(0, obuf, gcr->blklen, unsigned char);
		if ((gcr->err = gcry_cipher_encrypt(gcr->h, obuf, gcr->blklen, gcr->buffer, gcr->blklen)) != 0)
			croak("encrypt: %s", gcry_strerror(gcr->err));
		gcr->buffer[0] = '\0';
		RETVAL = newSVpvn(obuf, gcr->blklen);
		Safefree(obuf);
		/* DESTROY(gcr); */
    OUTPUT:
		RETVAL



SV *
cg_decrypt(gcr, in)
	Crypt_GCrypt gcr;
	SV *in;
    PREINIT:
		unsigned char *ibuf, *obuf;
		size_t len, ilen, dlen, plen;
		int error;
    CODE:
    	if (gcr->action != CG_ACTION_DECRYPT)
    		croak("start('decrypting') was not called");
    	
		ibuf = SvPV(in, ilen);
		if ((len = ilen % gcr->blklen) == 0) {
			len = ilen;
		} else {
			croak("input must be a multiple of blklen");
			unsigned char *b;
			len = ilen + gcr->blklen - len;
			New(0, b, len, unsigned char);
			memcpy(b, ibuf, ilen);
			memset(b + ilen, 0, len - ilen);
			ibuf = b;
		}
		New(0, obuf, len, unsigned char);
		if ((error = gcry_cipher_decrypt(gcr->h, obuf, len, ibuf, len)) != 0)
			croak("decrypt: %s", gcry_strerror(error));
		if (len != ilen)
			Safefree(ibuf);
		
		/* Remove padding */
		dlen = len;
    	switch (gcr->padding) {
			case CG_PADDING_STANDARD:
				plen = (int) obuf[len-1];
				if (obuf[len-1] == obuf[len-plen])
					dlen = len - plen;
	    		break;
			case CG_PADDING_NULL:
				dlen = strchr((char *)obuf, '\0') - (char *)obuf;
	    		break;
			case CG_PADDING_SPACE:
				/* This is not secure, we have to rewrite it: */
				dlen = strchr((char *)obuf, '\32') - (char *)obuf;
	    		break;
		}
		/* printf("dlen: %d\n", dlen); */
		RETVAL = newSVpvn(obuf, dlen);
		Safefree(obuf);
    OUTPUT:
		RETVAL

SV *
cg_sign(gcr, in)
	Crypt_GCrypt gcr;
	SV *in;
    PREINIT:
    	gcry_mpi_t in_mpi, out_mpi;
    	gcry_ac_data_t outdata;
		size_t len;
		const void *inbuf;
		const char *label;
		unsigned char outbuf;
    CODE:
    	in_mpi = gcry_mpi_new(0);
    	out_mpi = gcry_mpi_new(0);
    	inbuf = SvPV(in, len);
    	printf("inbuf: %s\n", inbuf);
    	gcry_mpi_scan( &in_mpi, GCRYMPI_FMT_STD, inbuf, strlen(inbuf), NULL );
    	printf("Key: %s\n", gcr->key_ac);
		gcr->err = gcry_ac_data_sign(gcr->h_ac, gcr->key_ac, in_mpi, &outdata);
		if (gcr->err) {
			croak( gcry_strerror(gcr->err) );
		}
    	printf("Here\n");
		gcr->err = gcry_ac_data_get_index (outdata, 0, 0, &label, &out_mpi);
    	printf("Before (%s)\n", label);
		gcry_mpi_print(GCRYMPI_FMT_STD, &outbuf, 1024, NULL, out_mpi);
    	printf("After\n");
		RETVAL = newSVpv(&outbuf, 0);
    OUTPUT:
		RETVAL

void
cg_start(gcr, act)
	Crypt_GCrypt gcr;
	SV *act;
    PREINIT:
		char *action;
		size_t len;
    CODE:
    	gcr->err = gcry_cipher_reset(gcr->h);
    	New(0, gcr->buffer, gcr->blklen, unsigned char);
    	gcr->buflen = 0;
    	action = SvPV(act, len);
    	switch (action[0]) {
    		case 'e':
    			gcr->action = CG_ACTION_ENCRYPT;
    			break;
    		case 'd':
    			gcr->action = CG_ACTION_DECRYPT;
    			break;
    	}

void
cg_setkey(gcr, ...)
	Crypt_GCrypt gcr;
	PREINIT:
		unsigned char *k, *pk, *s;
		unsigned char *mykey;
		gcry_ac_key_type_t keytype;
		gcry_ac_data_t keydata;
		gcry_mpi_t mpi;
		size_t len;
    CODE:
    	if (gcr->action == CG_ACTION_NONE)
    		croak("start() must be called before setkey()");
    	
		/* Set key for cipher */
		if (gcr->type == CG_TYPE_CIPHER) {
			Newz(0, k, gcr->keylen, unsigned char);
			k = SvPV(ST(1), len);
			/* If key is shorter than our algorithm's key size 
		  	 let's pad it with zeroes */
			if (len >= gcr->keylen) {
				mykey = k;
			} else {
				Newz(0, pk, gcr->keylen, unsigned char);
				memcpy(pk, k, len);
				memset(pk + len, 0, gcr->keylen - len);
				mykey = pk;
			}
			gcr->err = gcry_cipher_setkey(gcr->h, mykey,  gcr->keylen);
			if (gcr->err != 0) croak("setkey: %s", gcry_strerror(gcr->err));
		}
		
		/* Set key for asymmetric criptography */
		if (gcr->type == CG_TYPE_ASYMM) {
			k = SvPV(ST(2), len);
			
			/* Key type */
			keytype = -1;
			s = SvPV(ST(1), len);
			if (strcmp(s, "private") == 0) keytype = GCRY_AC_KEY_SECRET;
			if (strcmp(s, "public") == 0) keytype = GCRY_AC_KEY_PUBLIC;
			if (keytype == -1)
				croak("Key must be private or public");
			
			gcry_control(GCRYCTL_INIT_SECMEM, strlen(k));
			mpi = gcry_mpi_snew(0);
			/* gcry_mpi_scan( &mpi, GCRYMPI_FMT_STD, k, NULL, NULL ); */
			gcr->err = gcry_ac_data_new(&keydata);
			gcr->err = gcry_ac_data_set(keydata, GCRY_AC_FLAG_COPY, "s", mpi);
			gcr->err = gcry_ac_key_init(&gcr->key_ac, gcr->h_ac, keytype, keydata);
		}

void
cg_setiv(gcr, ...)
	Crypt_GCrypt gcr;
    PREINIT:
		char *iv;
		size_t len;
    CODE:
    	if (gcr->type != CG_TYPE_CIPHER)
    		croak("Can't call setiv when doing non-cipher operations");
		Newz(0, iv, gcr->blklen, char);
		if (items == 2) {
			char *param;
			param = SvPV(ST(1), len);
			if (len > gcr->blklen)
				len = gcr->blklen;
			memcpy(iv, param, len);
		} else if (items == 1) {
			len = 0;
		} else
			croak("Usage: $cipher->setiv([iv])");
		memset(iv + len, 0, gcr->blklen - len);
		gcry_cipher_setiv(gcr->h, iv, gcr->blklen);
		Safefree(iv);

void
cg_sync(gcr)
	Crypt_GCrypt gcr;
    CODE:
    	if (gcr->type != CG_TYPE_CIPHER)
    		croak("Can't call sync when doing non-cipher operations");
		gcry_cipher_sync(gcr->h);

int
cg_keylen(gcr)
	Crypt_GCrypt gcr;
    CODE:
    	if (gcr->type != CG_TYPE_CIPHER)
    		croak("Can't call keylen when doing non-cipher operations");
		RETVAL = gcr->keylen;
    OUTPUT:
		RETVAL

int
cg_blklen(gcr)
	Crypt_GCrypt gcr;
    CODE:
    	if (gcr->type != CG_TYPE_CIPHER)
    		croak("Can't call blklen when doing non-cipher operations");
		RETVAL = gcr->blklen;
    OUTPUT:
		RETVAL

void
cg_DESTROY(gcr)
	Crypt_GCrypt gcr;
    CODE:
    	if (gcr->type == CG_TYPE_CIPHER) {
			gcry_cipher_close(gcr->h);
		}
    	if (gcr->type == CG_TYPE_ASYMM) {
			gcry_ac_close(gcr->h_ac);
		}
		Safefree(gcr->buffer);
		Safefree(gcr);
