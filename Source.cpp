#include <NTL/ZZ.h>
#include <NTL/RR.h>
#include <array>
#include <vector>
#include <stdlib.h>
#include <time.h>
#include <algorithm>
#include <chrono>

using namespace std;
using namespace NTL;

// Defining global parameters(settings) of encryption scheme:
// bit-length of the integers in the public key
const long bits_in_pk = 290000;
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
	
	result = pk[subset[0]];
	for (int i = 1; i < subset.size(); i++) {
		result = result + pk[subset[i]];
	}
	
	r = RandomBits_ZZ(bits_in_noise);
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

const int OSIZE = 80;
const int N1 = 42;
const int N2 = 128;
const int N3 = 9;
const int N4 = 8;
const int N3_sum = 45;
const int SIZE = N1 + N2 + (N3_sum * N4);

void permutation(std::array<int, SIZE> &values){
    int nb, tmp;
    for ( int i = 0; i < SIZE; i++ ) values[i] = i;
  
    for (int i = SIZE - 1; i > 0; i--){
        nb = rand() & i;
        tmp = values[i];
        values[i] = values[nb];
        values[nb] = tmp;
	}
}

template<typename S>
S linear(std::array<S, SIZE> const &state){  
	S result = state[0];

	for (int i = 1; i < N1; i++) result +=state[i];

	return result;
}

template<typename S>
S quadratic(std::array<S, SIZE> const &state){
	S result = state[N1] * state[N1 + 1];
	for (int i = 2; i < N2; i += 2) result += state[N1 + i] * state[N1 + i + 1];

	return result;
}

template<typename S>
S triangular(std::array<S, SIZE> const &state){
	int it = N1 + N2;
	S result = state[it];

	for(int i = 0; i < N4; i++){
		int multiplications = 0;

		for(it = N1 + N2 + (i * N3_sum); it < N1 + N2 + ((i+1) * N3_sum); ){
			multiplications+= 1;
			S tmp = state[it];
      		//cout << it << " ";
      		it++;
      		for(int j = 0; j < multiplications - 1; j++){
        		tmp *= state[it];
        		//cout << it << " ";
        		it++;
      		}
      	//cout << endl;
      	result += tmp;

    	}
  	}

  	return result;
}

template<typename K, typename S, typename O>
void Flip(std::array<K, SIZE> const &key, std::array<S, SIZE> &state, std::array<O, OSIZE> &output)
{

  	std::array<int, SIZE> pm;

  	for (int i = 0; i < SIZE; i++) state[i] = key[i];

  	std::array<S, SIZE> alter_state;
  
  	//Iterate until you have enough output
  	for (int i = 0; i < OSIZE; i++){

    	//Ask for new permutation
    	permutation(pm);

    	/*for (auto const &v : pm) {
      		std::cout << v << " ";
    	}
    	cout << endl;*/

    	//Copy initial state to altered state using generated permutation
    	for (int j = 0; j < SIZE; j++) alter_state[pm[j]] = state[j];

    	output[i] = linear(alter_state) + quadratic(alter_state) + triangular(alter_state);
  }

}

int main()
{
	ZZ sk;
	ZZ q, r;
	int posit;
	array<ZZ, integers_in_pk> pk;
    // Timer
    auto start = std::chrono::steady_clock::now();
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds;

	RR::SetPrecision(10*bits_in_pk);
	
	srand(time(NULL));

	// generete odd number as secret key
	do {
		RandomLen(sk, bits_in_sk);
	} while ((sk % ZZ(2)) == ZZ(0));

	ZZ upperBound = power2_ZZ(bits_in_pk);	
	ZZ upperBound_divided_p = upperBound/sk;
	// generate whole public key
	do {
		// x_i = sk * q_i + r_i
		for (int i = 0; i < integers_in_pk; i++) {
			/*
			RandomLen(q, bits_in_pk);
			q = q / sk;*/
			RandomBnd(q, upperBound_divided_p);
			//cout << "q = " << q << endl;

			r = RandomBits_ZZ(bits_in_noise);
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
	} while ((!IsOdd(pk[0])) || ( IsOdd(customModulus(pk[0],sk))));

	/*array<ZZ, 80> test_vector;
	array<ZZ, 80> test_vector_result;
	ZZ enc_text;
	ZZ dec_text;
    ZZ add_one = ZZ(1);
    ZZ add_one_enc;
    ZZ multiply_one = ZZ(1);
    ZZ multiply_one_enc;
	int same = 0;
	int different = 0;

	//cout << endl << "Plain text:" << endl;
	for (int i = 0; i < 80; i++) {
		test_vector[i] = RandomBits_ZZ(1);
		cout << test_vector[i];
	}

	add_one_enc = encrypt(add_one, pk);

	//cout << endl << "Deciphered text: " << endl;
	for (int i = 0; i < 80; i++) {
		enc_text = encrypt(test_vector[i], pk);

        enc_text = enc_text * add_one_enc;

		test_vector_result[i] = decrypt(enc_text, sk);
		cout << test_vector_result[i];
		if (test_vector[i] != test_vector_result[i])
			different += 1;
		else
			same += 1;
	}
	
	cout << endl << "Same:" << same;
	cout << endl << "Different:" << different;*/

    array<unsigned long, SIZE> key; 
    generate(key.begin(), key.end(), [] { return rand() & 1; });


    std::array<unsigned long, SIZE> state;
    std::array<unsigned long, OSIZE> output;
  
    srand(0);
    start = std::chrono::steady_clock::now();
    Flip(key, state, output);
    end = std::chrono::steady_clock::now();

    elapsed_seconds = end - start;
    cout << "\tBinary Flip: \t\t\t"
            << elapsed_seconds.count() << " us"
            << std::endl;

    for (auto const &v : output) {
        std::cout << v % 2;
    }
    cout << endl;
 
    std::array<ZZ, SIZE> h_key;
    ZZ temp_key_element;
    for (size_t i = 0; i < SIZE; i++) {
        temp_key_element = ZZ(key[i]);
        h_key[i] = encrypt(temp_key_element, pk);
    }

    std::array<ZZ, SIZE> h_state;
    std::array<ZZ, OSIZE> h_output;

    srand(0);
    start = std::chrono::steady_clock::now();
    Flip(h_key, h_state, h_output);
    end = std::chrono::steady_clock::now();

    elapsed_seconds = end - start;
    cout << "\tHomomorphic Flip: \t\t"
            << elapsed_seconds.count()  << " s"
            << std::endl;

    for (int i = 0; i < OSIZE; i++){
        cout << decrypt(h_output[i], sk);
    }

	return 0;

}
