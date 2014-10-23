/*
 ===========================================================================
 Crypt::GCrypt

 Perl interface to the GNU Cryptographic library
 
 Author: Alessandro Ranellucci <aar@cpan.org>
 
 Use this software AT YOUR OWN RISK.
 ===========================================================================
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <gcrypt.h>
#include <string.h>

#ifdef USE_ITHREADS
    #ifdef I_PTHREAD
        #include <pthread.h>
        #define HAVE_PTHREAD
    #else
        #warning "Perl ithreads not available or not implemented with Pthread: building a non-threadsafe Crypt::GCrypt"
    # endif
#endif


static const char my_name[] = "Crypt::GCrypt";
static const char author[] = "Alessandro Ranellucci <aar@cpan.org>";

enum cg_type
{
    CG_TYPE_CIPHER,
    CG_TYPE_ASYMM,
    CG_TYPE_DIGEST
};
enum cg_action
{
    CG_ACTION_NONE,
    CG_ACTION_ENCRYPT,
    CG_ACTION_DECRYPT
};
enum cg_padding
{
    CG_PADDING_NONE,
    CG_PADDING_STANDARD,
    CG_PADDING_NULL,
    CG_PADDING_SPACE
};

struct Crypt_GCrypt_s {
    int type;
    int action;
    gcry_cipher_hd_t h;
    gcry_ac_handle_t h_ac;
    gcry_md_hd_t h_md;
    gcry_ac_key_t key_ac;
    gcry_error_t err;
    int mode;
    int padding;
    unsigned char *buffer;
    STRLEN buflen, blklen, keylen;
    int need_to_call_finish;
    int buffer_is_decrypted;
};
typedef struct Crypt_GCrypt_s *Crypt_GCrypt;

/* return the offset of padding or -1 if none */
int find_padding (Crypt_GCrypt gcr, unsigned char *string, size_t string_len) {
    unsigned char last_char = string[string_len-1];
    size_t i, offset;
    void *p;
    
    switch (gcr->padding) {
        case CG_PADDING_STANDARD:
            /* padding length is last_char */
            for (i = 1; i <= last_char; ++i) {
                if (string[string_len-i] != last_char) return -1;
            }
            return string_len-last_char;
            
        case CG_PADDING_NULL:
            p = memchr((char *) string, '\0', string_len);
            if (p == NULL) return -1;
            
            offset = (int) p - (int) string;
            for (i = offset; i < string_len; ++i) {
                if (string[string_len-i] != '\0') return -1;
            }
            return offset;
            
        case CG_PADDING_SPACE:
            p = memchr((char *) string, '\32', string_len);
            if (p == NULL) return -1;
            
            offset = (int) p - (int) string;
            for (i = offset; i < string_len; ++i) {
                if (string[string_len-i] != '\32') return -1;
            }
            return offset;
    }
    return -1;
}

#ifdef HAVE_PTHREAD
    GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

void
init_library() {
  gcry_error_t ret;
  if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
    /* we just need to make sure that the right version is available */
    if (!gcry_check_version(GCRYPT_VERSION))
      croak("libgcrypt version mismatch (needed: %s)", GCRYPT_VERSION);
    return;
  }
  /* else, we need to go ahead with the full initialization: */
  #ifdef HAVE_PTHREAD
    ret = gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    if (gcry_err_code(ret) != GPG_ERR_NO_ERROR)
    croak("could not initialize libgcrypt for threads (%d: %s/%s)", 
      gcry_err_code(ret),
      gcry_strsource(ret),
      gcry_strerror(ret));
  #endif
  
  if (!gcry_check_version(GCRYPT_VERSION))
    croak("libgcrypt version mismatch (needed: %s)", GCRYPT_VERSION);

  gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
}


MODULE = Crypt::GCrypt        PACKAGE = Crypt::GCrypt    PREFIX = cg_

SV *
cg_built_against_version()
    CODE:
        init_library();
        RETVAL = newSVpvn(GCRYPT_VERSION, strlen(GCRYPT_VERSION));
    OUTPUT:
        RETVAL

SV *
cg_gcrypt_version()
    INIT:
        const char * v;
    CODE:
        init_library();
        v = gcry_check_version(NULL);
        RETVAL = newSVpvn(v, strlen(v));
    OUTPUT:
        RETVAL

Crypt_GCrypt
cg_new(...)
    PROTOTYPE: @
    INIT:
        char *s, *algo_s, *mode_s, *key_s;
        int i, algo, mode;
        unsigned int c_flags, ac_flags, md_flags;
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
        RETVAL->need_to_call_finish = 0;
        RETVAL->buffer_is_decrypted = 0;
        RETVAL->buffer = NULL;
        c_flags = 0;
        ac_flags = 0;
        md_flags = 0;
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
                if (strcmp(s, "digest") == 0)
                    RETVAL->type = CG_TYPE_DIGEST;
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
                if (strcmp(s, "none") == 0)
                    RETVAL->padding = CG_PADDING_NONE;
                if (strcmp(s, "standard") == 0)
                    RETVAL->padding = CG_PADDING_STANDARD;
                if (strcmp(s, "null") == 0)
                    RETVAL->padding = CG_PADDING_NULL;
            }
            if (strcmp(s, "secure") == 0) {
                if (SvTRUE(ST(i+1))) {
                   c_flags |= GCRY_CIPHER_SECURE;
                   md_flags |= GCRY_MD_FLAG_SECURE;
                }
            }
            if (strcmp(s, "hmac") == 0) {
                key_s = SvPV(ST(i+1), RETVAL->keylen);
                md_flags |= GCRY_MD_FLAG_HMAC;
            }
            if (strcmp(s, "enable_sync") == 0) {
                if (SvTRUE(ST(i+1))) c_flags |= GCRY_CIPHER_ENABLE_SYNC;
            }
            i = i + 2;
        }
        if (RETVAL->type == -1)
            croak("No valid type specified for Crypt::GCrypt->new()");
        if (!algo_s)
            croak("No algorithm specified for Crypt::GCrypt->new()");

        init_library();

        if (RETVAL->type == CG_TYPE_CIPHER) {
            /* Checking algorithm */
            if (!(algo = gcry_cipher_map_name(algo_s)))
                croak("Unknown cipher algorithm %s", algo_s);
            RETVAL->blklen = gcry_cipher_get_algo_blklen(algo);
            RETVAL->keylen = gcry_cipher_get_algo_keylen(algo);
            
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
        if (RETVAL->type == CG_TYPE_DIGEST) {
            if (!(algo = gcry_md_map_name(algo_s)))
                croak("Unknown digest algorithm %s", algo_s);

        RETVAL->err = gcry_md_open(&RETVAL->h_md, algo, md_flags);
            if (RETVAL->h_md == NULL) XSRETURN_UNDEF;

        if (md_flags & GCRY_MD_FLAG_HMAC) {
            /* what if this overwrites the earlier error value? */
            RETVAL->err = gcry_md_setkey(RETVAL->h_md, key_s, RETVAL->keylen);
        }
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
        char *ibuf, *curbuf, *obuf;
        size_t len, ilen, buflen;
    CODE:
        if (gcr->action != CG_ACTION_ENCRYPT)
            croak("start('encrypting') was not called");
        
        ibuf = SvPV(in, ilen);
        
        if (gcr->padding == CG_PADDING_NONE && ilen % gcr->blklen > 0)
            croak("'None' padding requires that input to ->encrypt() is supplied as a multiple of blklen");
        
        /* Get total buffer+ibuf length */
        Newz(0, curbuf, ilen + gcr->buflen, char);
        memcpy(curbuf, gcr->buffer, gcr->buflen);
        memcpy(curbuf+gcr->buflen, ibuf, ilen);
        
        if ((len = (ilen+gcr->buflen) % gcr->blklen) == 0) {
            len = ilen+gcr->buflen;
            gcr->buffer[0] = '\0';
            gcr->buflen = 0;
        } else {
            char *tmpbuf;
            len = (ilen+gcr->buflen) - len;   /* len contiene i byte da scrivere effettivemente */
            
            Newz(0, tmpbuf, len, char);
            memcpy(tmpbuf, curbuf, len);
            memcpy(gcr->buffer, curbuf+len, (ilen+gcr->buflen)-len);
            gcr->buflen = (ilen+gcr->buflen)-len;
            Safefree(curbuf);
            curbuf = tmpbuf;
        }

        /* Encrypt data */
        New(0, obuf, len, char);
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
        char *obuf;
        size_t rlen, return_len, padding_length;
    CODE:
        if (gcr->type != CG_TYPE_CIPHER)
            croak("Can't call finish when doing non-cipher operations");
        gcr->need_to_call_finish = 0;
        if (gcr->action == CG_ACTION_ENCRYPT) {
            
            if (gcr->buflen < gcr->blklen) {
                unsigned char *tmpbuf;
                rlen = gcr->blklen - gcr->buflen;
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
            Newz(0, obuf, gcr->blklen, char);
            if ((gcr->err = gcry_cipher_encrypt(gcr->h, obuf, gcr->blklen, gcr->buffer, gcr->blklen)) != 0)
                croak("encrypt: %s", gcry_strerror(gcr->err));
            gcr->buffer[0] = '\0';
            gcr->buflen = 0;
            RETVAL = newSVpvn(obuf, gcr->blklen);
            Safefree(obuf);
            
        } else {  /* CG_ACTION_DECRYPT */
            
            /* decrypt remaining ciphertext if any */
            New(0, obuf, gcr->buflen, char);
            return_len = gcr->buflen;
            if (gcr->buflen > 0) {
                if (gcr->buffer_is_decrypted == 1) {
                    Move(gcr->buffer, obuf, gcr->buflen, char);
                } else {
                    if ((gcr->err = gcry_cipher_decrypt(gcr->h, obuf, return_len, gcr->buffer, gcr->buflen)) != 0)
                        croak("decrypt: %s", gcry_strerror(gcr->err));
                }
                gcr->buffer[0] = '\0';
                gcr->buflen = 0;
                
                /* Remove padding */
                return_len = find_padding(gcr, (unsigned char *) obuf, return_len);
            }
            
            RETVAL = newSVpvn(obuf, return_len);
            Safefree(obuf);
        }
    OUTPUT:
        RETVAL



SV *
cg_decrypt(gcr, in)
    Crypt_GCrypt gcr;
    SV *in;
    PREINIT:
        unsigned char *ibuf, *obuf, *ciphertext, *decrypted_buffer;
        size_t total_len, len, ilen;
        int ciphertext_offset;
    CODE:
        if (gcr->action != CG_ACTION_DECRYPT)
            croak("start('decrypting') was not called");
        
        ibuf = (unsigned char *) SvPV(in, ilen);
        if ((ilen % gcr->blklen) > 0 || ilen == 0)
            croak("input must be a multiple of blklen");
        
        /* Concatenate buffer and input to get total length of ciphertext */
        total_len = gcr->buflen + ilen;  /* total_len is a multiple of blklen */
        Newz(0, ciphertext, total_len, unsigned char);
        Move(gcr->buffer, ciphertext, gcr->buflen, unsigned char);
        Move(ibuf, ciphertext+gcr->buflen, ilen, unsigned char);
        
        /* if our buffer was decrypted by the previous run of this method,
           we set a ciphertext_offset to avoid re-decrypting such plaintext
           coming from the buffer */
        ciphertext_offset = (gcr->buffer_is_decrypted == 1) ? gcr->buflen : 0;
        
        /* strip last block and move it to buffer */
        len = total_len - gcr->blklen;  /* len is the length of plaintext we're returning */
        Move(ciphertext+len, gcr->buffer, (total_len - len), unsigned char);
        gcr->buflen = gcr->blklen;
        
        /* do actual decryption */
        New(0, obuf, len, unsigned char);
        Copy(ciphertext, obuf, ciphertext_offset, unsigned char);
        if (len-ciphertext_offset > 0) { /* that is, if we have something to decrypt */
            if ((gcr->err = gcry_cipher_decrypt(gcr->h, obuf+ciphertext_offset, len-ciphertext_offset, ciphertext+ciphertext_offset, len-ciphertext_offset)) != 0)
                croak("decrypt: %s", gcry_strerror(gcr->err));
        }
        Safefree(ciphertext);
        
        /* OPTIMIZATION for compatibility with implementations of Crypt::GCrypt <= 1.17:
           decrypt buffer and check if it seems padded */
        if ((gcr->err = gcry_cipher_decrypt(gcr->h, gcr->buffer, gcr->buflen, NULL, 0)) != 0) /* in-place decryption */
                         croak("decrypt: %s", gcry_strerror(gcr->err));
        gcr->buffer_is_decrypted = 1;
        if (find_padding(gcr, gcr->buffer, gcr->buflen) == -1) {
            /* if the string doesn't appear to be padded, let's append it to the
               output so that users who don't call ->finish() don't break their applications */
            Renew(obuf, len + gcr->buflen, unsigned char);
            Move(gcr->buffer, obuf+len, gcr->buflen, unsigned char);
            len = len + gcr->buflen;
            gcr->buffer[0] = '\0';
            gcr->buflen = 0;
            gcr->buffer_is_decrypted = 0;
        }
        RETVAL = newSVpvn((char *) obuf, len);
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
        char* outbuf;
    CODE:
        /*
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
        gcry_mpi_print(GCRYMPI_FMT_STD, outbuf, 1024, NULL, out_mpi);
        printf("After\n");
        RETVAL = newSVpv(outbuf, 0);
        */
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
        Safefree(gcr->buffer);
        New(0, gcr->buffer, gcr->blklen, unsigned char);
        gcr->buflen = 0;
        gcr->need_to_call_finish = 1;
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
        char *k, *s;
        char *mykey, *buf;
        gcry_ac_key_type_t keytype;
        gcry_ac_data_t keydata;
        gcry_mpi_t mpi;
        size_t len;
    CODE:
        /* Set key for cipher */
        if (gcr->type == CG_TYPE_CIPHER) {
            buf = NULL;
            mykey = SvPV(ST(1), len);
            /* If key is shorter than our algorithm's key size 
               let's pad it with zeroes */
            if (len < gcr->keylen) {
                Newz(0, buf, gcr->keylen, char);
                memcpy(buf, mykey, len);
                mykey = buf;
            }
            gcr->err = gcry_cipher_setkey(gcr->h, mykey, gcr->keylen);
            if (gcr->err != 0) croak("setkey: %s", gcry_strerror(gcr->err));
            Safefree(buf);
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
        char *buf, *param;
        size_t len;
    CODE:
        buf = NULL;
        if (gcr->type != CG_TYPE_CIPHER)
            croak("Can't call setiv when doing non-cipher operations");
        if (items == 2) {
            param = SvPV(ST(1), len);
            if (len < gcr->blklen) {
                Newz(0, buf, gcr->blklen, char);
                memcpy(buf, param, len);
                param = buf;
            }
        } else if (items == 1) {
            Newz(0, buf, gcr->blklen, char);
            param = buf;
        } else
            croak("Usage: $cipher->setiv([iv])");
        gcry_cipher_setiv(gcr->h, param, gcr->blklen);
        Safefree(buf);

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
cg_reset(gcr)
    Crypt_GCrypt gcr;
    CODE:
        if (gcr->type != CG_TYPE_DIGEST)
            croak("Can't call reset when doing non-digest operations");
        gcry_md_reset(gcr->h_md);

void
cg_write(gcr, in)
    Crypt_GCrypt gcr;
    SV *in;
    PREINIT:
        char *ibuf;
        size_t ilen;
    CODE:
        if (gcr->type != CG_TYPE_DIGEST)
            croak("Can't call write when doing non-digest operations.");
        ibuf = SvPV(in, ilen);
        gcry_md_write(gcr->h_md, ibuf, ilen);

SV *
cg_read(gcr)
    Crypt_GCrypt gcr;
    PREINIT:
        unsigned char *output;
        size_t len;
    CODE:
        if (gcr->type != CG_TYPE_DIGEST)
            croak("Can't call read when doing non-digest operations.");
        output = gcry_md_read(gcr->h_md, 0);
        len = gcry_md_get_algo_dlen(gcry_md_get_algo(gcr->h_md));
        RETVAL = newSVpvn((const char *) output, len);
    OUTPUT:
        RETVAL

int
cg_digest_length(gcr)
    Crypt_GCrypt gcr;
    CODE:
        if (gcr->type != CG_TYPE_DIGEST)
            croak("Can't call digest_length when doing non-digest operations");
        RETVAL = gcry_md_get_algo_dlen(gcry_md_get_algo(gcr->h_md));
    OUTPUT:
        RETVAL

Crypt_GCrypt
cg_clone(gcr)
    Crypt_GCrypt gcr;
    CODE:
        if (gcr->type != CG_TYPE_DIGEST)
            croak("Crypt::GCrypt::clone() is only currently defined for digest objects");
        
        New(0, RETVAL, 1, struct Crypt_GCrypt_s);
        Copy(gcr, RETVAL, 1, struct Crypt_GCrypt_s);
        /* if we allow clone() for cipher objects, we should duplicate the buffer */
        RETVAL->err = gcry_md_copy(&RETVAL->h_md, gcr->h_md);
        if (RETVAL->h_md == NULL) XSRETURN_UNDEF;
    OUTPUT:
        RETVAL

int
cg_digest_algo_available(algo)
    SV *algo;
    PREINIT:
        const char *algo_s;
        int algo_id;
    CODE:
        algo_s = SvPV_nolen(algo);
        init_library();
        algo_id = gcry_md_map_name(algo_s);
        if (algo_id) {
            if (gcry_md_test_algo(algo_id))
                RETVAL = 0;
            else
                RETVAL = 1;
        } else {
            RETVAL = 0;
        }
    OUTPUT:
        RETVAL

int
cg_cipher_algo_available(algo)
    SV *algo;
    PREINIT:
        const char *algo_s;
        int algo_id;
    CODE:
        algo_s = SvPV_nolen(algo);
        init_library();
        algo_id = gcry_cipher_map_name(algo_s);
        if (algo_id) {
            if (gcry_cipher_algo_info(algo_id, GCRYCTL_TEST_ALGO, 0, 0))
                RETVAL = 0;
            else
                RETVAL = 1;
        } else {
            RETVAL = 0;
        }
    OUTPUT:
        RETVAL

void
cg_DESTROY(gcr)
    Crypt_GCrypt gcr;
    CODE:
        if (gcr->type == CG_TYPE_CIPHER) gcry_cipher_close(gcr->h);
        if (gcr->type == CG_TYPE_ASYMM)  gcry_ac_close(gcr->h_ac);
        if (gcr->type == CG_TYPE_DIGEST) gcry_md_close(gcr->h_md);
        
        if (gcr->need_to_call_finish == 1)
            warn("WARNING: the ->finish() method was not called after encryption/decryption.");
            
        Safefree(gcr->buffer);
        Safefree(gcr);

