#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <keygen_interface.h>

#define FIELD_BITS 384
#define FIELD_BYTES 48
uint8_t cset[] = "BCDFGHJKMPQRTVWXY2346789";

static void pack(uint32_t *raw, uint32_t *pid, uint32_t *hash, uint32_t *sig)
{
	raw[0] = pid[0] | ((hash[0] & 1) << 31);
	raw[1] = (hash[0] >> 1) | ((sig[0] & 0x1f) << 27);
	raw[2] = (sig[0] >> 5) | (sig[1] << 27);
	raw[3] = sig[1] >> 5;
}

static void endian(uint8_t *data, int len)
{
	int i;
	for (i = 0; i < len/2; i++) {
		uint8_t temp;
		temp = data[i];
		data[i] = data[len-i-1];
		data[len-i-1] = temp;
	}
}



void base24(uint8_t *c, uint32_t *x)
{
	uint8_t y[16];
	int i;
	BIGNUM *z;


	memcpy(y, x, sizeof(y));
	for (i = 15; y[i] == 0; i--) {} i++;
	endian(y, i);
 	z = BN_bin2bn(y, i, NULL);

	c[25] = 0;
	for (i = 24; i >= 0; i--) {
		uint8_t t = BN_div_word(z, 24);
		c[i] = cset[t];
	}

	BN_free(z);
}



void generate(uint8_t *pkey, EC_GROUP *ec, EC_POINT *generator, BIGNUM *order, BIGNUM *priv, uint32_t *pid)
{
	BN_CTX *ctx = BN_CTX_new();
        BIGNUM *k = BN_new(), *s = BN_new(), *x = BN_new(), *y = BN_new();
        EC_POINT *r = EC_POINT_new(ec);
	
	uint32_t bkey[4], hash[1];
        uint8_t buf[FIELD_BYTES], md[20];
        SHA_CTX h_ctx;

	uint8_t t[4];
        t[0] = pid[0] & 0xff;
        t[1] = (pid[0] & 0xff00) >> 8;
        t[2] = (pid[0] & 0xff0000) >> 16;
        t[3] = (pid[0] & 0xff000000) >> 24;

do {
        	BN_pseudo_rand(k, FIELD_BITS, -1, 0);
        	EC_POINT_mul(ec, r, NULL, generator, k, ctx);
        	EC_POINT_get_affine_coordinates_GFp(ec, r, x, y, ctx);
        
        	SHA1_Init(&h_ctx);
        	SHA1_Update(&h_ctx, t, 4);

        	memset(buf, 0, FIELD_BYTES); // Sicher ist sicher
        	BN_bn2bin(x, buf);
        	endian(buf, FIELD_BYTES);
        	SHA1_Update(&h_ctx, buf, FIELD_BYTES);
        
        	memset(buf, 0, FIELD_BYTES);
        	BN_bn2bin(y, buf);
        	endian(buf, FIELD_BYTES);
        	SHA1_Update(&h_ctx, buf, FIELD_BYTES);
        
	        SHA1_Final(md, &h_ctx);
        	hash[0] = ((md[0] | (md[1] << 8) | (md[2] << 16) | (md[3] << 24)) >> 4) & 0xfffffff;
        
        	BN_copy(s, priv);
        	BN_mul_word(s, hash[0]);
        	BN_mod_add(s, s, k, order, ctx);
        
        	uint32_t sig[2] = {0};
        	int sig_len = BN_bn2bin(s, (uint8_t *)sig);
        	endian((uint8_t *)sig, sig_len);
        
        	pack(bkey, pid, hash, sig);
    	} while (bkey[3] >= 0x40000);

    	base24(pkey, bkey);
	
	BN_free(k); BN_free(s); BN_free(x); BN_free(y);
    	EC_POINT_free(r);
    	BN_CTX_free(ctx);
}


extern "C" void generate_key_interface(char* buffer) {
    BIGNUM *a = BN_new(), *b = BN_new(), *p = BN_new(), *gx = BN_new(), *gy = BN_new();
    BIGNUM *n = BN_new(), *priv = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_hex2bn(&p, "92ddcf14cb9e71f4489a2e9ba350ae29454d98cb93bdbcc07d62b502ea12238ee904a8b20d017197aae0c103b32713a9");
    BN_set_word(a, 1); BN_set_word(b, 0);
    BN_hex2bn(&gx, "46E3775ECE21B0898D39BEA57050D422A0AF989E497962BAEE2CB17E0A28D5360D5476B8DC966443E37A14F1AEF37742");
    BN_hex2bn(&gy, "7C8E741D2C34F4478E325469CD491603D807222C9C4AC09DDB2B31B3CE3F7CC191B3580079932BC6BEF70BE27604F65E");
    BN_hex2bn(&n, "DB6B4C58EFBAFD");
    BN_hex2bn(&priv, "565B0DFF8496C8");

    EC_GROUP *ec = EC_GROUP_new_curve_GFp(p, a, b, ctx);
    EC_POINT *g = EC_POINT_new(ec);
    EC_POINT_set_affine_coordinates_GFp(ec, g, gx, gy, ctx);

    uint8_t pkey[26];
    uint32_t pid[1] = { 640000000 << 1 };

    generate(pkey, ec, g, n, priv, pid);

    int j = 0;
    for (int i = 0; i < 25; i++) {
        buffer[j++] = (char)pkey[i];
        if (i != 24 && i % 5 == 4) buffer[j++] = '-';
    }
    buffer[j] = '\0';

    EC_POINT_free(g); EC_GROUP_free(ec);
    BN_free(a); BN_free(b); BN_free(p); BN_free(gx); BN_free(gy); BN_free(n); BN_free(priv);
    BN_CTX_free(ctx);
}
