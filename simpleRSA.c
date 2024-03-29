#include <stdio.h>
#include <math.h>

//create GCD function
unsigned long int GCD(unsigned long int a, unsigned long int b){
    unsigned long int c;
    while(1){
        c = a % b;
        if(c==0) return b;
        a = b;
        b = c;
    }
    return 0;
}

int main(){
    //rsa requires a p, q, n, e, d, phi;
    double p = 3;
    double q = 7;
    double n = p*q;
    double phi = (p-1)*(q-1);

    //public key
    // e stands for encrypt
    double e = 2;

    // checks if e is greater than 0 with phi
    while(e < phi){
        if(GCD(e,phi) == 1) break;
        else e++;
    }
    
    // generating private key
    //decrypt key d
    unsigned long int d;

    //k 
    double k = 2;
    double msg = 12; // length
    printf("Message data = %lf",msg);
    printf("\np = %lf",p);
    printf("\nq = %lf",q);
    printf("\nn = pq = %lf",n);
    printf("\nphi = %lf",phi);
    printf("\ne = %lf",e);
   

    //ensure that the decryption key satifies the check
    d = (1+(k*phi))/e;
    printf("\nd = %lf",d);
    double c = pow(msg,e);// encrypt the message with the encryption key
    c = fmod(c,n);
    printf("\nEncrypted data = %lf",c);
    double m = pow(c,d); // decrypt the message
    m = fmod(m,n);
    printf("\nOriginal Message Sent = %lf",m);

    
    
    
    
    return 0;
}
