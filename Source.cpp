#include <NTL/ZZ.h>
#include <NTL/RR.h>
#include <array>
#include <vector>
#include <stdlib.h>
#include <time.h>
#include <algorithm>

using namespace std;
using namespace NTL;

// Defining global parameters(settings) of encryption scheme:
// bit-length of the integers in the public key
const long bits_in_pk = 29000;
// bit-length of the secret key
const long bits_in_sk = 988;
// bit-length of the noise
const long bits_in_noise = 26;
// number of integers in the public key
const long integers_in_pk = 188;
// number of integers in subset of public key, that is used for encryption - half of the nb. of integers in pk
const long integers_in_enc_subset = integers_in_pk / 2;


//
ZZ customModulus(ZZ c, ZZ p) {
	ZZ result;
	RR tmp;
	ZZ tmp_integer;
	RR local_c = MakeRR(c, 0);
	RR local_p = MakeRR(p, 0);
	double a = 0.5;

	tmp = local_c / local_p;
	//cout << tmp << endl;
	tmp_integer = c / p;

	if ((tmp - MakeRR(tmp_integer, 0)) > RR(a))
		tmp_integer += 1;
	//cout << tmp_integer << endl;

	result = c - p * tmp_integer;
	
	return result;
}

// Create subset from the set - set has hald-of-the-key size
vector<int> generate_subset(int subset_size, int set_size) {
	vector<int> set;
	vector<int> subset;
	int posit;

	for (int i = 1; i < set_size; i++)
		set.push_back(i);

	for (int i = 0; i < subset_size; i++) {
		posit = rand() % set.size();
		//cout << endl << "Position: " << posit << endl;
		subset.push_back(set[posit]);
		//cout << "Pushed value: " << set[posit] << endl << endl;
		set.erase(set.begin() + (posit));
	}
	return subset;

}

// encrypt plaintext m using public key pk
ZZ encrypt(ZZ m, array<ZZ, integers_in_pk> pk) {

	ZZ result;
	ZZ r, power_ro;
	vector<int> subset;

	subset = generate_subset(integers_in_enc_subset, integers_in_pk);

	result = subset[0];
	for (int i = 1; i < subset.size(); i++) {
		result = result + pk[subset[i]];
	}

	r = RandomBits_ZZ(2 ^ bits_in_noise);
	if (rand() % 2 == 0)
		r = r * ZZ(-1);
	result = m + 2 * r + 2 * result;

	result = customModulus( result , pk[0] );

	return result;
}

// decrypt ciphertext c using secret key sk
ZZ decrypt(ZZ c, ZZ sk) {
	ZZ result;

	result = customModulus(customModulus(c, sk), ZZ(2));

	return result;
}

int main()
{
	ZZ sk;
	ZZ q, r;
	int posit;
	array<ZZ, integers_in_pk> pk;

	srand(time(NULL));

	// generete odd number as secret key
	do {
		RandomLen(sk, bits_in_sk);
	} while (sk % 2 == 0);

	// generate whole public key
	do {
		// x_i = sk * q_i + r_i
		for (int i = 0; i < integers_in_pk; i++) {
			RandomLen(q, bits_in_pk);
			q = q / sk;
			//cout << "q = " << q << endl;

			r = RandomBits_ZZ(2 ^ bits_in_noise);
			if (rand() % 2 == 0)
				r = r * ZZ(-1);
			//cout << "r = " << r << endl;
			pk[i] = sk * q + r;

			if (i == 0)
				posit = 0;
			else if (pk[i] > pk[posit])
				posit = i;

		}
		ZZ tmp = pk[0];
		pk[0] = pk[posit];
		pk[posit] = tmp;

		// pk[0] musi byt parne + pk[0] % sk musi byt neparne
	} while ((pk[0] % 2 != 0) ||
			 ( ( pk[0] % sk ) % 2 != 1 ));

	array<ZZ, 80> test_vector;
	array<ZZ, 80> test_vector_result;
	ZZ enc_text;
	ZZ dec_text;
	int same = 0;
	int different = 0;

	//cout << endl << "Plain text:" << endl;
	for (int i = 0; i < 80; i++) {
		test_vector[i] = RandomBits_ZZ(1);
		cout << test_vector[i];
	}

	//cout << endl << "Deciphered text: " << endl;
	for (int i = 0; i < 80; i++) {
		enc_text = encrypt(test_vector[i], pk);
		test_vector_result[i] = decrypt(enc_text, sk);
		cout << test_vector_result[i];
		if (test_vector[i] != test_vector_result[i])
			different += 1;
		else
			same += 1;
	}
	
	cout << endl << "Same:" << same;
	cout << endl << "Different:" << different;

	string s;
	cin >> s;

	return 0;

}
