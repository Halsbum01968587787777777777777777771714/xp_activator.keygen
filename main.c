#define STRICT
#define UNICODE
#define _UNICODE
#define _WIN32_IE 0x0600
#define _WIN32_WINNT 0x0501

#include <windows.h>
#include <commctrl.h>
#include <stdint.h>
#include <intrin.h>
#include <keygen_interface.h>
#include "resource.h"
#include <stdio.h>

HICON hIcon[2];

#define assert(x) /*nothing*/
#define BAD 0xFFFFFFFFFFFFFFFFull
#define MOD 0x16A6B036D7F2A79ULL
#define NON_RESIDUE 43

typedef int64_t i64;
typedef uint64_t ui64;

extern void generate_key_interface(char* buffer);

static const ui64 f[6] = {0, 0x21840136C85381ULL, 0x44197B83892AD0ULL, 0x1400606322B3B04ULL, 0x1400606322B3B04ULL, 1};

typedef struct { ui64 u[2]; ui64 v[2]; } TDivisor;

// --- Arithmetic ---

static ui64 residue_add(ui64 x, ui64 y) { ui64 z = x + y; if (z >= MOD) z -= MOD; return z; }
static ui64 residue_sub(ui64 x, ui64 y) { ui64 z = x - y; if (x < y) z += MOD; return z; }

static uint64_t __umul128(uint64_t a0, uint64_t b0, uint64_t *hi)
{
	uint64_t a = a0 >> 32, b = (uint32_t)a0, c = b0 >> 32, d = (uint32_t)b0;
	uint64_t ad = __emulu(a, d), bd = __emulu(b, d);
	uint64_t adbc = ad + __emulu(b, c);
	uint64_t adbc_carry = (adbc < ad);
	uint64_t lo = bd + (adbc << 32);
	uint64_t lo_carry = (lo < bd);
	*hi = __emulu(a, c) + (adbc >> 32) + (adbc_carry << 32) + lo_carry;
	return lo;
}

static ui64 ui128_quotient_mod(ui64 lo, ui64 hi)
{
	ui64 p1, p1hi, p2hi;
	__umul128(lo, 0x604fa6a1c6346a87, &p1);
	ui64 p1lo = __umul128(lo, 0x2d351c6d04f8b, &p1hi);
	ui64 p2lo = __umul128(hi, 0x604fa6a1c6346a87, &p2hi);
	ui64 s = p1lo + p2lo; unsigned sc = (s < p1lo);
	s += p1; sc += (s < p1);
	ui64 p3hi, p3lo = __umul128(hi, 0x2d351c6d04f8b, &p3hi);
	p3lo += p1hi + p2hi + sc; p3hi += (p3lo < (p1hi + p2hi + sc));
	return (p3lo >> 42) | (p3hi << 22);
}

static ui64 residue_mul(ui64 x, ui64 y)
{
	ui64 hi, lo = __umul128(x, y, &hi);
	return lo - ui128_quotient_mod(lo, hi) * MOD;
}

static ui64 residue_pow(ui64 x, ui64 y)
{
	if (!y) return 1;
	ui64 cur = x;
	while (!(y & 1)) { cur = residue_mul(cur, cur); y >>= 1; }
	ui64 res = cur;
	while ((y >>= 1)) { cur = residue_mul(cur, cur); if (y & 1) res = residue_mul(res, cur); }
	return res;
}

static ui64 inverse(ui64 u, ui64 v)
{
	i64 xu = 1, xv = 0, tmp;
	ui64 v0 = v;
	while (u > 1) {
		ui64 d = v / u, r = v % u;
		tmp = u; u = r; v = tmp;
		tmp = xu; xu = xv - (i64)d * xu; xv = tmp;
	}
	xu += (xu < 0 ? (i64)v0 : 0);
	return xu;
}

static ui64 residue_inv(ui64 x) { return inverse(x, MOD); }

static ui64 residue_sqrt(ui64 what)
{
	if (!what) return 0;
	ui64 g = NON_RESIDUE, z, y, r, x, b, t;
	ui64 e = 0, q = MOD - 1;
	while (!(q & 1)) { e++; q >>= 1; }
	z = residue_pow(g, q); y = z; r = e;
	x = residue_pow(what, (q - 1) / 2);
	b = residue_mul(residue_mul(what, x), x);
	x = residue_mul(what, x);
	while (b != 1) {
		ui64 m = 0, b2 = b;
		do { m++; b2 = residue_mul(b2, b2); } while (b2 != 1);
		if (m == r) return BAD;
		t = residue_pow(y, 1 << (r - m - 1));
		y = residue_mul(t, t); r = m;
		x = residue_mul(x, t); b = residue_mul(b, y);
	}
	return (residue_mul(x, x) != what) ? BAD : x;
}

// --- Divisor / Polynomial ---

int find_divisor_v(TDivisor* d)
{
	ui64 v1, f2[6];
	int i, j;
	for (i = 0; i < 6; i++) f2[i] = f[i];
	const ui64 u0 = d->u[0], u1 = d->u[1];
	for (j = 4; j--; ) {
		f2[j]   = residue_sub(f2[j],   residue_mul(u0, f2[j+2]));
		f2[j+1] = residue_sub(f2[j+1], residue_mul(u1, f2[j+2]));
		f2[j+2] = 0;
	}
	const ui64 f0 = f2[0], f1 = f2[1];
	const ui64 u0d = residue_add(u0, u0);
	const ui64 coeff2 = residue_sub(residue_mul(u1, u1), residue_add(u0d, u0d));
	const ui64 coeff1 = residue_sub(residue_add(f0, f0), residue_mul(f1, u1));
	if (coeff2 == 0) {
		if (coeff1 == 0) { if (f1 == 0) {} return 0; }
		ui64 sqr = residue_mul(residue_mul(f1, f1), residue_inv(residue_add(coeff1, coeff1)));
		v1 = residue_sqrt(sqr);
		if (v1 == BAD) return 0;
	} else {
		ui64 disc = residue_add(residue_mul(f0, f0),
			residue_mul(f1, residue_sub(residue_mul(f1, u0), residue_mul(f0, u1))));
		disc = residue_sqrt(disc);
		if (disc == BAD) return 0;
		disc = residue_add(disc, disc);
		ui64 inv = residue_inv(coeff2);
		ui64 root = residue_mul(residue_add(coeff1, disc), inv);
		v1 = residue_sqrt(root);
		if (v1 == BAD) {
			root = residue_mul(residue_sub(coeff1, disc), inv);
			v1 = residue_sqrt(root);
			if (v1 == BAD) return 0;
		}
	}
	d->v[0] = residue_mul(residue_add(f1, residue_mul(u1, residue_mul(v1, v1))),
	                       residue_inv(residue_add(v1, v1)));
	d->v[1] = v1;
	return 1;
}

static int polynomial_mul(int adeg, const ui64 a[], int bdeg, const ui64 b[], int prevdeg, ui64 res[])
{
	if (adeg < 0 || bdeg < 0) return prevdeg;
	int i, j;
	for (i = prevdeg + 1; i <= adeg + bdeg; i++) res[i] = 0;
	prevdeg = i - 1;
	for (i = 0; i <= adeg; i++)
		for (j = 0; j <= bdeg; j++)
			res[i+j] = residue_add(res[i+j], residue_mul(a[i], b[j]));
	while (prevdeg >= 0 && res[prevdeg] == 0) --prevdeg;
	return prevdeg;
}

static int polynomial_div_monic(int adeg, ui64 a[], int bdeg, const ui64 b[], ui64* quot)
{
	assert(bdeg >= 0); assert(b[bdeg] == 1);
	int i, j;
	for (i = adeg - bdeg; i >= 0; i--) {
		ui64 q = a[i + bdeg];
		if (quot) quot[i] = q;
		for (j = 0; j < bdeg; j++)
			a[i+j] = residue_sub(a[i+j], residue_mul(q, b[j]));
		a[i+j] = 0;
	}
	i += bdeg;
	while (i >= 0 && a[i] == 0) i--;
	return i;
}

static void polynomial_xgcd(int adeg, const ui64 a[3], int bdeg, const ui64 b[3],
	int* pgcddeg, ui64 gcd[3], int* pm1deg, ui64 m1[3], int* pm2deg, ui64 m2[3])
{
	int sdeg = -1; ui64 s[3] = {0,0,0};
	int m1deg = 0; m1[0] = 1; m1[1] = m1[2] = 0;
	int tdeg = 0;  ui64 t[3] = {1,0,0};
	int m2deg = -1; m2[0] = m2[1] = m2[2] = 0;
	int rdeg = bdeg; ui64 r[3] = {b[0],b[1],b[2]};
	int gcddeg = adeg; gcd[0]=a[0]; gcd[1]=a[1]; gcd[2]=a[2];
	while (rdeg >= 0) {
		if (rdeg > gcddeg) {
#define SWAP2(A,B) {unsigned _t=A;A=B;B=_t;}
#define SWAP2I(A,B) {int _t=A;A=B;B=_t;}
#define SWAP64(A,B) {ui64 _t=A;A=B;B=_t;}
			SWAP2(rdeg, gcddeg); SWAP2I(sdeg, m1deg); SWAP2I(tdeg, m2deg);
			SWAP64(r[0],gcd[0]); SWAP64(r[1],gcd[1]); SWAP64(r[2],gcd[2]);
			SWAP64(s[0],m1[0]);  SWAP64(s[1],m1[1]);  SWAP64(s[2],m1[2]);
			SWAP64(t[0],m2[0]);  SWAP64(t[1],m2[1]);  SWAP64(t[2],m2[2]);
			continue;
		}
		int delta = gcddeg - rdeg;
		ui64 mult = residue_mul(gcd[gcddeg], residue_inv(r[rdeg]));
		for (int i = 0; i <= rdeg; i++)
			gcd[i+delta] = residue_sub(gcd[i+delta], residue_mul(mult, r[i]));
		while (gcddeg >= 0 && gcd[gcddeg] == 0) gcddeg--;
		for (int i = 0; i <= sdeg; i++)
			m1[i+delta] = residue_sub(m1[i+delta], residue_mul(mult, s[i]));
		if (m1deg < sdeg+delta) m1deg = sdeg+delta;
		while (m1deg >= 0 && m1[m1deg] == 0) m1deg--;
		for (int i = 0; i <= tdeg; i++)
			m2[i+delta] = residue_sub(m2[i+delta], residue_mul(mult, t[i]));
		if (m2deg < tdeg+delta) m2deg = tdeg+delta;
		while (m2deg >= 0 && m2[m2deg] == 0) m2deg--;
	}
	*pgcddeg = gcddeg; *pm1deg = m1deg; *pm2deg = m2deg;
}

static int u2poly(const TDivisor* src, ui64 pu[3], ui64 pv[2])
{
	if (src->u[1] != BAD) {
		pu[0]=src->u[0]; pu[1]=src->u[1]; pu[2]=1;
		pv[0]=src->v[0]; pv[1]=src->v[1]; return 2;
	}
	if (src->u[0] != BAD) {
		pu[0]=src->u[0]; pu[1]=1;
		pv[0]=src->v[0]; pv[1]=0; return 1;
	}
	pu[0]=1; pv[0]=pv[1]=0; return 0;
}

static void divisor_add(const TDivisor* src1, const TDivisor* src2, TDivisor* dst)
{
	ui64 u1[3], u2[3], v1[2], v2[2];
	int u1deg = u2poly(src1, u1, v1);
	int u2deg = u2poly(src2, u2, v2);
	int d1deg, e1deg, e2deg;
	ui64 d1[3], e1[3], e2[3];
	polynomial_xgcd(u1deg, u1, u2deg, u2, &d1deg, d1, &e1deg, e1, &e2deg, e2);
	ui64 bv[3] = {residue_add(v1[0],v2[0]), residue_add(v1[1],v2[1]), 0};
	int bdeg = (bv[1]==0 ? (bv[0]==0 ? -1 : 0) : 1);
	int ddeg, c1deg, c2deg;
	ui64 d[3], c1[3], c2[3];
	polynomial_xgcd(d1deg, d1, bdeg, bv, &ddeg, d, &c1deg, c1, &c2deg, c2);
	ui64 dmult = residue_inv(d[ddeg]);
	int i;
	for (i = 0; i < ddeg; i++) d[i] = residue_mul(d[i], dmult);
	d[i] = 1;
	for (i = 0; i <= c1deg; i++) c1[i] = residue_mul(c1[i], dmult);
	for (i = 0; i <= c2deg; i++) c2[i] = residue_mul(c2[i], dmult);
	ui64 u[5]; int udeg = polynomial_mul(u1deg, u1, u2deg, u2, -1, u);
	ui64 v[7], tmp[7]; int vdeg, tmpdeg;
	v[0] = residue_sub(v2[0],v1[0]); v[1] = residue_sub(v2[1],v1[1]);
	tmpdeg = polynomial_mul(e1deg, e1, 1, v, -1, tmp);
	vdeg = polynomial_mul(u1deg, u1, tmpdeg, tmp, -1, v);
	vdeg = polynomial_mul(d1deg, d1, 1, v1, vdeg, v);
	for (i = 0; i <= vdeg; i++) v[i] = residue_mul(v[i], c1[0]);
	memcpy(tmp, f, 6*sizeof(f[0])); tmpdeg = 5;
	tmpdeg = polynomial_mul(1, v1, 1, v2, tmpdeg, tmp);
	vdeg = polynomial_mul(c2deg, c2, tmpdeg, tmp, vdeg, v);
	if (ddeg > 0) {
		ui64 udiv[5];
		polynomial_div_monic(udeg, u, ddeg, d, udiv); udeg -= ddeg;
		polynomial_div_monic(udeg, udiv, ddeg, d, u);  udeg -= ddeg;
		if (vdeg >= 0) {
			polynomial_div_monic(vdeg, v, ddeg, d, udiv); vdeg -= ddeg;
			memcpy(v, udiv, (vdeg+1)*sizeof(v[0]));
		}
	}
	vdeg = polynomial_div_monic(vdeg, v, udeg, u, NULL);
	while (udeg > 2) {
		tmpdeg = polynomial_mul(vdeg, v, vdeg, v, -1, tmp);
		for (i = 0; i <= tmpdeg && i <= 5; i++) tmp[i] = residue_sub(f[i], tmp[i]);
		for (; i <= tmpdeg; i++) tmp[i] = residue_sub(0, tmp[i]);
		for (; i <= 5; i++) tmp[i] = f[i];
		tmpdeg = i - 1;
		ui64 udiv[5];
		polynomial_div_monic(tmpdeg, tmp, udeg, u, udiv);
		udeg = tmpdeg - udeg;
		ui64 mult = residue_inv(udiv[udeg]);
		for (i = 0; i < udeg; i++) u[i] = residue_mul(udiv[i], mult);
		u[i] = 1;
		for (i = 0; i <= vdeg; i++) v[i] = residue_sub(0, v[i]);
		vdeg = polynomial_div_monic(vdeg, v, udeg, u, NULL);
	}
	if (udeg == 2) {
		dst->u[0]=u[0]; dst->u[1]=u[1];
		dst->v[0]=(vdeg>=0?v[0]:0); dst->v[1]=(vdeg>=1?v[1]:0);
	} else if (udeg == 1) {
		dst->u[0]=u[0]; dst->u[1]=BAD;
		dst->v[0]=(vdeg>=0?v[0]:0); dst->v[1]=BAD;
	} else {
		dst->u[0]=dst->u[1]=dst->v[0]=dst->v[1]=BAD;
	}
}

#define divisor_double(src, dst) divisor_add(src, src, dst)

static void divisor_mul(const TDivisor* src, ui64 mult, TDivisor* dst)
{
	if (!mult) { dst->u[0]=dst->u[1]=dst->v[0]=dst->v[1]=BAD; return; }
	TDivisor cur = *src;
	while (!(mult & 1)) { divisor_double(&cur, &cur); mult >>= 1; }
	*dst = cur;
	while ((mult >>= 1)) { divisor_double(&cur, &cur); if (mult & 1) divisor_add(dst, &cur, dst); }
}

static void divisor_mul128(const TDivisor* src, ui64 lo, ui64 hi, TDivisor* dst)
{
	if (!lo && !hi) { dst->u[0]=dst->u[1]=dst->v[0]=dst->v[1]=BAD; return; }
	TDivisor cur = *src;
	while (!(lo & 1)) {
		divisor_double(&cur, &cur);
		lo >>= 1; if (hi & 1) lo |= (1ULL << 63); hi >>= 1;
	}
	*dst = cur;
	for (;;) {
		lo >>= 1; if (hi & 1) lo |= (1ULL << 63); hi >>= 1;
		if (!lo && !hi) break;
		divisor_double(&cur, &cur);
		if (lo & 1) divisor_add(dst, &cur, dst);
	}
}

// --- SHA1 / Mix / Unmix ---

static unsigned rol(unsigned x, int s) { return (x << s) | (x >> (32 - s)); }

static void sha1_single_block(unsigned char in[64], unsigned char out[20])
{
	unsigned a=0x67452301, b=0xEFCDAB89, c=0x98BADCFE, d=0x10325476, e=0xC3D2E1F0;
	unsigned w[80]; size_t i;
	for (i = 0; i < 16; i++)
		w[i] = in[4*i]<<24 | in[4*i+1]<<16 | in[4*i+2]<<8 | in[4*i+3];
	for (i = 16; i < 80; i++)
		w[i] = rol(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
#define SHA1_ROUND(F, K) { unsigned t = rol(a,5)+(F)+e+w[i]+(K); e=d; d=c; c=rol(b,30); b=a; a=t; }
	for (i=0;  i<20; i++) SHA1_ROUND((b&c)|(~b&d),         0x5A827999)
	for (i=20; i<40; i++) SHA1_ROUND(b^c^d,                0x6ED9EBA1)
	for (i=40; i<60; i++) SHA1_ROUND((b&c)|(b&d)|(c&d),    0x8F1BBCDC)
	for (i=60; i<80; i++) SHA1_ROUND(b^c^d,                0xCA62C1D6)
#undef SHA1_ROUND
	a+=0x67452301; b+=0xEFCDAB89; c+=0x98BADCFE; d+=0x10325476; e+=0xC3D2E1F0;
#define PUT4(V,O) out[O]=V>>24; out[O+1]=V>>16; out[O+2]=V>>8; out[O+3]=V;
	PUT4(a,0) PUT4(b,4) PUT4(c,8) PUT4(d,12) PUT4(e,16)
#undef PUT4
}

static void Mix(unsigned char* buf, size_t bufSz, const unsigned char* key, size_t keySz)
{
	unsigned char sha1_in[64], sha1_out[20];
	size_t half = bufSz / 2;
	for (int k = 0; k < 4; k++) {
		memset(sha1_in, 0, 64);
		memcpy(sha1_in, buf+half, half);
		memcpy(sha1_in+half, key, keySz);
		sha1_in[half+keySz] = 0x80;
		sha1_in[62] = (half+keySz)*8 / 0x100;
		sha1_in[63] = (half+keySz)*8;
		sha1_single_block(sha1_in, sha1_out);
		for (size_t i = half&~3; i < half; i++)
			sha1_out[i] = sha1_out[i+4-(half&3)];
		for (size_t i = 0; i < half; i++) {
			unsigned char t = buf[i+half];
			buf[i+half] = buf[i] ^ sha1_out[i];
			buf[i] = t;
		}
	}
}

static void Unmix(unsigned char* buf, size_t bufSz, const unsigned char* key, size_t keySz)
{
	unsigned char sha1_in[64], sha1_out[20];
	size_t half = bufSz / 2;
	for (int k = 0; k < 4; k++) {
		memset(sha1_in, 0, 64);
		memcpy(sha1_in, buf, half);
		memcpy(sha1_in+half, key, keySz);
		sha1_in[half+keySz] = 0x80;
		sha1_in[62] = (half+keySz)*8 / 0x100;
		sha1_in[63] = (half+keySz)*8;
		sha1_single_block(sha1_in, sha1_out);
		for (size_t i = half&~3; i < half; i++)
			sha1_out[i] = sha1_out[i+4-(half&3)];
		for (size_t i = 0; i < half; i++) {
			unsigned char t = buf[i];
			buf[i] = buf[i+half] ^ sha1_out[i];
			buf[i+half] = t;
		}
	}
}

// --- Key Generation ---

#define ERR_TOO_SHORT         1
#define ERR_TOO_LARGE         2
#define ERR_INVALID_CHARACTER 3
#define ERR_INVALID_CHECK_DIGIT 4
#define ERR_UNKNOWN_VERSION   5
#define ERR_UNLUCKY           6

#define CHARTYPE wchar_t

static int generate(const CHARTYPE* installation_id_str, CHARTYPE confirmation_id[49])
{
	unsigned char iid[19] = {0};
	size_t iid_len = 0;
	const CHARTYPE* p = installation_id_str;
	size_t count = 0, total = 0;
	unsigned check = 0;
	for (; *p; p++) {
		if (*p == ' ' || *p == '-') continue;
		int dig = *p - '0';
		if (dig < 0 || dig > 9) return ERR_INVALID_CHARACTER;
		if (count == 5 || p[1] == 0) {
			if (!count) return (total == 45) ? ERR_TOO_LARGE : ERR_TOO_SHORT;
			if (dig != check % 7)
				return (count < 5) ? ERR_TOO_SHORT : ERR_INVALID_CHECK_DIGIT;
			check = count = 0; continue;
		}
		check += (count % 2 ? dig * 2 : dig);
		count++; total++;
		if (total > 45) return ERR_TOO_LARGE;
		unsigned char carry = dig;
		for (size_t i = 0; i < iid_len; i++) {
			unsigned x = iid[i] * 10 + carry;
			iid[i] = x & 0xFF; carry = x >> 8;
		}
		if (carry) iid[iid_len++] = carry;
	}
	if (total != 41 && total < 45) return ERR_TOO_SHORT;
	for (; iid_len < sizeof(iid); iid_len++) iid[iid_len] = 0;

	static const unsigned char iid_key[4] = {0x6A, 0xC8, 0x5E, 0xD4};
	Unmix(iid, total == 41 ? 17 : 19, iid_key, 4);
	if (iid[18] >= 0x10) return ERR_UNKNOWN_VERSION;

#pragma pack(push, 1)
	struct { ui64 HardwareID, ProductIDLow; unsigned char ProductIDHigh; unsigned short KeySHA1; } parsed;
#pragma pack(pop)
	memcpy(&parsed, iid, sizeof(parsed));

	unsigned pid1 = parsed.ProductIDLow & ((1<<17)-1);
	unsigned pid2 = (parsed.ProductIDLow >> 17) & ((1<<10)-1);
	unsigned pid3 = (parsed.ProductIDLow >> 27) & ((1<<25)-1);
	unsigned ver  = (parsed.ProductIDLow >> 52) & 7;
	unsigned pid4 = (parsed.ProductIDLow >> 55) | (parsed.ProductIDHigh << 9);
	if (ver != (total == 41 ? 4 : 5)) return ERR_UNKNOWN_VERSION;

	unsigned char keybuf[16];
	memcpy(keybuf, &parsed.HardwareID, 8);
	ui64 pidMixed = (ui64)pid1<<41 | (ui64)pid2<<58 | (ui64)pid3<<17 | pid4;
	memcpy(keybuf+8, &pidMixed, 8);

	TDivisor d;
	unsigned char attempt;
	for (attempt = 0; attempt <= 0x80; attempt++) {
		union { unsigned char buffer[14]; struct { ui64 lo, hi; }; } u;
		u.lo = u.hi = 0;
		u.buffer[7] = attempt;
		Mix(u.buffer, 14, keybuf, 16);
		ui64 x2 = ui128_quotient_mod(u.lo, u.hi);
		ui64 x1 = u.lo - x2 * MOD;
		x2++;
		d.u[0] = residue_sub(residue_mul(x1,x1), residue_mul(NON_RESIDUE, residue_mul(x2,x2)));
		d.u[1] = residue_add(x1, x1);
		if (find_divisor_v(&d)) break;
	}
	if (attempt > 0x80) return ERR_UNLUCKY;
	divisor_mul128(&d, 0x04e21b9d10f127c1, 0x40da7c36d44c, &d);

	union { struct { ui64 lo, hi; }; struct { uint32_t e[4]; }; } enc;
	if (d.u[0] == BAD) {
		enc.lo = __umul128(MOD+2, MOD, &enc.hi);
	} else if (d.u[1] == BAD) {
		enc.lo = __umul128(MOD+1, d.u[0], &enc.hi);
		enc.lo += MOD; enc.hi += (enc.lo < MOD);
	} else {
		ui64 x1 = (d.u[1]%2 ? d.u[1]+MOD : d.u[1]) / 2;
		ui64 x2sqr = residue_sub(residue_mul(x1,x1), d.u[0]);
		ui64 x2 = residue_sqrt(x2sqr);
		if (x2 == BAD) {
			x2 = residue_sqrt(residue_mul(x2sqr, residue_inv(NON_RESIDUE)));
			enc.lo = __umul128(MOD+1, MOD+x2, &enc.hi);
			enc.lo += x1; enc.hi += (enc.lo < x1);
		} else {
			ui64 x1a = residue_sub(x1,x2), y1 = residue_sub(d.v[0], residue_mul(d.v[1],x1a));
			ui64 x2a = residue_add(x1,x2), y2 = residue_sub(d.v[0], residue_mul(d.v[1],x2a));
			if (x1a > x2a) { ui64 t=x1a; x1a=x2a; x2a=t; }
			if ((y1^y2)&1) { ui64 t=x1a; x1a=x2a; x2a=t; }
			enc.lo = __umul128(MOD+1, x1a, &enc.hi);
			enc.lo += x2a; enc.hi += (enc.lo < x2a);
		}
	}

	unsigned char decimal[35];
	size_t i;
	for (i = 0; i < 35; i++) {
		unsigned c  = enc.e[3] % 10; enc.e[3] /= 10;
		unsigned c2 = ((ui64)c <<32 | enc.e[2]) % 10; enc.e[2] = ((ui64)c <<32 | enc.e[2]) / 10;
		unsigned c3 = ((ui64)c2<<32 | enc.e[1]) % 10; enc.e[1] = ((ui64)c2<<32 | enc.e[1]) / 10;
		unsigned c4 = ((ui64)c3<<32 | enc.e[0]) % 10; enc.e[0] = ((ui64)c3<<32 | enc.e[0]) / 10;
		decimal[34-i] = c4;
	}
	CHARTYPE* q = confirmation_id;
	for (i = 0; i < 7; i++) {
		if (i) *q++ = '-';
		unsigned char* pp = decimal + i*5;
		q[0]=pp[0]+'0'; q[1]=pp[1]+'0'; q[2]=pp[2]+'0';
		q[3]=pp[3]+'0'; q[4]=pp[4]+'0';
		q[5] = ((pp[0]+pp[1]*2+pp[2]+pp[3]*2+pp[4]) % 7) + '0';
		q += 6;
	}
	*q = 0;
	return 0;
}

// --- GUI ---

static wchar_t strings[14][256];

static CLSID licdllCLSID   = {0xACADF079,0xCBCD,0x4032,{0x83,0xF2,0xFA,0x47,0xC4,0xDB,0x09,0x6F}};
static IID   licenseAgentIID = {0xB8CBAD79,0x3F1F,0x481A,{0xBB,0x0C,0xE7,0xBB,0xD7,0x7B,0xDD,0xD1}};

#undef INTERFACE
#define INTERFACE ICOMLicenseAgent
DECLARE_INTERFACE_(ICOMLicenseAgent, IDispatch)
{
	STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID* ppvObj) PURE;
	STDMETHOD_(ULONG,AddRef)(THIS) PURE;
	STDMETHOD_(ULONG,Release)(THIS) PURE;
	STDMETHOD(GetTypeInfoCount)(THIS_ UINT FAR* pctinfo) PURE;
	STDMETHOD(GetTypeInfo)(THIS_ UINT itinfo, LCID lcid, ITypeInfo FAR* FAR* pptinfo) PURE;
	STDMETHOD(GetIDsOfNames)(THIS_ REFIID riid, OLECHAR FAR* FAR* rgszNames, UINT cNames, LCID lcid, DISPID FAR* rgdispid) PURE;
	STDMETHOD(Invoke)(THIS_ DISPID dispidMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS FAR* pdispparams, VARIANT FAR* pvarResult, EXCEPINFO FAR* pexcepinfo, UINT FAR* puArgErr) PURE;
	STDMETHOD(Initialize)(THIS_ ULONG dwBPC, ULONG dwMode, BSTR bstrLicSource, ULONG* pdwRetCode) PURE;
	STDMETHOD(GetFirstName)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetFirstName)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetLastName)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetLastName)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetOrgName)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetOrgName)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetEmail)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetEmail)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetPhone)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetPhone)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetAddress1)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetAddress1)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetCity)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetCity)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetState)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetState)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetCountryCode)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetCountryCode)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetCountryDesc)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetCountryDesc)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetZip)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetZip)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetIsoLanguage)(THIS_ ULONG* pdwVal) PURE;
	STDMETHOD(SetIsoLanguage)(THIS_ ULONG dwNewVal) PURE;
	STDMETHOD(GetMSUpdate)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetMSUpdate)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetMSOffer)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetMSOffer)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetOtherOffer)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetOtherOffer)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(GetAddress2)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(SetAddress2)(THIS_ BSTR bstrNewVal) PURE;
	STDMETHOD(AsyncProcessHandshakeRequest)(THIS_ LONG bReviseCustInfo) PURE;
	STDMETHOD(AsyncProcessNewLicenseRequest)(THIS) PURE;
	STDMETHOD(AsyncProcessReissueLicenseRequest)(THIS) PURE;
	STDMETHOD(AsyncProcessReviseCustInfoRequest)(THIS) PURE;
	STDMETHOD(GetAsyncProcessReturnCode)(THIS_ ULONG* pdwRetCode) PURE;
	STDMETHOD(AsyncProcessDroppedLicenseRequest)(THIS) PURE;
	STDMETHOD(GenerateInstallationId)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(DepositConfirmationId)(THIS_ BSTR bstrVal, ULONG* pdwRetCode) PURE;
	STDMETHOD(GetExpirationInfo)(THIS_ ULONG* pdwWPALeft, ULONG* pdwEvalLeft) PURE;
	STDMETHOD(AsyncProcessRegistrationRequest)(THIS) PURE;
	STDMETHOD(ProcessHandshakeRequest)(THIS_ LONG bReviseCustInfo) PURE;
	STDMETHOD(ProcessNewLicenseRequest)(THIS) PURE;
	STDMETHOD(ProcessDroppedLicenseRequest)(THIS) PURE;
	STDMETHOD(ProcessReissueLicenseRequest)(THIS) PURE;
	STDMETHOD(ProcessReviseCustInfoRequest)(THIS) PURE;
	STDMETHOD(EnsureInternetConnection)(THIS) PURE;
	STDMETHOD(SetProductKey)(THIS_ LPWSTR pszNewProductKey) PURE;
	STDMETHOD(GetProductID)(THIS_ BSTR* pbstrVal) PURE;
	STDMETHOD(VerifyCheckDigits)(THIS_ BSTR bstrCIDIID, LONG* pbValue) PURE;
};

static void OnActivationIdChange(HWND hDlg)
{
	wchar_t iid[256], cid[49];
	iid[0] = 0;
	GetDlgItemText(hDlg, 101, iid, 256);
	int err = generate(iid, cid);
	const wchar_t* msg = cid;
	if (err) { msg = strings[err]; EnableWindow(GetDlgItem(hDlg, 104), FALSE); }
	else      { EnableWindow(GetDlgItem(hDlg, 104), TRUE); SendMessage(hDlg, DM_SETDEFID, 104, 0); }
	SetDlgItemText(hDlg, 103, msg);
}

static BOOL ComInitialized = FALSE;
static ICOMLicenseAgent* LicenseAgent = NULL;

static BOOL LoadLicenseManager(HWND hParent)
{
	if (!ComInitialized) {
		if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) {
			MessageBox(hParent, strings[10], strings[8], MB_ICONSTOP);
			return FALSE;
		}
		ComInitialized = TRUE;
	}
	if (!LicenseAgent) {
		HRESULT hr = CoCreateInstance(&licdllCLSID, NULL, CLSCTX_INPROC_SERVER, &licenseAgentIID, (void**)&LicenseAgent);
		int ok = 0;
		if (SUCCEEDED(hr)) {
			ULONG ret;
			hr = LicenseAgent->lpVtbl->Initialize(LicenseAgent, 0xC475, 3, 0, &ret);
			if (SUCCEEDED(hr) && ret == 0) ok = 1;
			else { LicenseAgent->lpVtbl->Release(LicenseAgent); LicenseAgent = NULL; }
		}
		if (!ok) { MessageBox(hParent, strings[10], strings[8], MB_ICONSTOP); return FALSE; }
	}
	ULONG wpaLeft = 0, evalLeft = 0;
	if (FAILED(LicenseAgent->lpVtbl->GetExpirationInfo(LicenseAgent, &wpaLeft, &evalLeft))) {
		MessageBox(hParent, strings[11], strings[8], MB_ICONSTOP);
		LicenseAgent->lpVtbl->Release(LicenseAgent); LicenseAgent = NULL;
		return FALSE;
	}
	if (wpaLeft == 0x7FFFFFFF) {
		MessageBox(hParent, strings[12], strings[9], MB_ICONWARNING);
		LicenseAgent->lpVtbl->Release(LicenseAgent); LicenseAgent = NULL;
		return FALSE;
	}
	return TRUE;
}

static void GetIdFromSystem(HWND hDlg)
{
	if (!LoadLicenseManager(hDlg)) return;
	SetDlgItemText(hDlg, 103, strings[7]);
	EnableWindow(GetDlgItem(hDlg, 102), FALSE);
	UpdateWindow(hDlg);
	BSTR iid = NULL;
	if (FAILED(LicenseAgent->lpVtbl->GenerateInstallationId(LicenseAgent, &iid)) || !iid)
		MessageBox(hDlg, strings[13], strings[8], MB_ICONSTOP);
	else { SetDlgItemText(hDlg, 101, iid); SysFreeString(iid); }
	OnActivationIdChange(hDlg);
	EnableWindow(GetDlgItem(hDlg, 102), TRUE);
}

static void PutIdToSystem(HWND hDlg)
{
	if (!LoadLicenseManager(hDlg)) return;
	ULONG ret;
	wchar_t cid[256];
	GetDlgItemText(hDlg, 103, cid, 256);
	SetDlgItemText(hDlg, 103, strings[7]);
	EnableWindow(GetDlgItem(hDlg, 102), FALSE);
	EnableWindow(GetDlgItem(hDlg, 104), FALSE);
	UpdateWindow(hDlg);
	BSTR cidBstr = SysAllocString(cid);
	HRESULT hr = LicenseAgent->lpVtbl->DepositConfirmationId(LicenseAgent, cidBstr, &ret);
	SysFreeString(cidBstr);
	EnableWindow(GetDlgItem(hDlg, 102), TRUE);
	EnableWindow(GetDlgItem(hDlg, 104), TRUE);
	SetDlgItemText(hDlg, 103, cid);
	if (FAILED(hr) || ret) { MessageBox(hDlg, strings[13], strings[8], MB_ICONSTOP); return; }
	MessageBox(hDlg, strings[0], strings[9], MB_ICONINFORMATION);
}

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg) {
	case WM_CTLCOLORSTATIC: {
		HDC hdc = (HDC)wParam;
		SetTextColor(hdc, RGB(0,0,0));
		SetBkColor(hdc, GetSysColor(COLOR_3DFACE));
		return (LRESULT)GetSysColorBrush(COLOR_3DFACE);
	}
	case WM_CTLCOLOREDIT: {
		HDC hdc = (HDC)wParam;
		SetTextColor(hdc, RGB(0,0,0));
		SetBkColor(hdc, GetSysColor(COLOR_3DFACE));
		return (LRESULT)GetSysColorBrush(COLOR_3DFACE);
	}
	case WM_INITDIALOG: {
		EnableWindow(GetDlgItem(hDlg, 104), FALSE);
		HBITMAP hImg = (HBITMAP)LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDB_KEY_BITMAP),
		                                  IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
		if (hImg) SendDlgItemMessage(hDlg, 200, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hImg);
		if (hIcon[0]) SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon[0]);
		if (hIcon[1]) SendMessage(hDlg, WM_SETICON, ICON_BIG,   (LPARAM)hIcon[1]);
		return TRUE;
	}
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) == 101 && HIWORD(wParam) == EN_CHANGE) {
			int len = GetWindowTextLengthA(GetDlgItem(hDlg, 101));
			EnableWindow(GetDlgItem(hDlg, 104), len >= 54);
		}
		switch (wParam) {
		case IDCANCEL:
			EndDialog(hDlg, 0); break;
		case MAKEWPARAM(101, EN_CHANGE):
			OnActivationIdChange(hDlg); break;
		case 102:
			GetIdFromSystem(hDlg); break;
		case 104:
			PutIdToSystem(hDlg); break;
		case 105: {
			char key[26];
			generate_key_interface(key);
			SetDlgItemTextA(hDlg, 106, key);
			int r = MessageBoxW(hDlg,
				L"Would you like to install this key? / \u0412\u044b \u0445\u043e\u0442\u0438\u0442\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u044d\u0442\u043e\u0442 \u043a\u043b\u044e\u0447? / Moechten Sie diesen Key installieren?",
				L"Confirmation / \u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 / Bestaetigung",
				MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
			if (r == IDYES) {
				char params[200];
				snprintf(params, sizeof(params), "C:\\Windows\\System32\\slmgr.vbs /ipk %s", key);
				SHELLEXECUTEINFOA sei = {0};
				sei.cbSize = sizeof(sei); sei.fMask = SEE_MASK_NOCLOSEPROCESS;
				sei.hwnd = hDlg; sei.lpVerb = "runas";
				sei.lpFile = "wscript.exe"; sei.lpParameters = params; sei.nShow = SW_HIDE;
				if (ShellExecuteExA(&sei)) {
					WaitForSingleObject(sei.hProcess, INFINITE);
					CloseHandle(sei.hProcess);
					MessageBoxW(hDlg,
						L"Product Key wurde an das System uebergeben. / \u041a\u043b\u044e\u0447 \u043f\u0440\u043e\u0434\u0443\u043a\u0442\u0430 \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u0443. / The product key has been sent to the system.",
						L"Erfolg / Success / \u0423\u0441\u043f\u0435\u0445", MB_ICONINFORMATION);
				} else {
					MessageBoxW(hDlg,
						L"Fehler: Konnte slmgr nicht ausfuehren. / \u041e\u0448\u0438\u0431\u043a\u0430: \u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u044c slmgr. / Error: Failed to execute slmgr.",
						L"Fehler / Error / \u041e\u0448\u0438\u0431\u043a\u0430", MB_ICONERROR);
				}
			}
			break;
		}
		}
		return TRUE;
	}
	return FALSE;
}

void main()
{
	INITCOMMONCONTROLSEX cc = {sizeof(INITCOMMONCONTROLSEX),
	                           ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES | ICC_USEREX_CLASSES};
	InitCommonControlsEx(&cc);
	for (int i = 0; i < 14; i++)
		LoadString(NULL, i, strings[i], 256);
	hIcon[0] = (HICON)LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1),
	                            IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR | LR_SHARED);
	hIcon[1] = (HICON)LoadImage(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1),
	                            IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR | LR_SHARED);
	INT_PTR status = DialogBox(NULL, MAKEINTRESOURCE(100), NULL, &DialogProc);
	for (int i = 0; i < 2; i++) DestroyIcon(hIcon[i]);
	if (LicenseAgent)  LicenseAgent->lpVtbl->Release(LicenseAgent);
	if (ComInitialized) CoUninitialize();
	ExitProcess(status);
}
