/*  Name & E-mail: Ji Houn Huh (jhuh009@ucr.edu)
 *  Lab Section: 23
 *  Assignment: Custom Project
 *  Project Description: Transmit encrypted message 
 *  
 *  I acknowledge all content contained herein, excluding template or example
 *  code, is my own original work.
 */
#include <avr/io.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "io.c"
#include "bit.h"
#include "timer.h"


//--------Find GCD function --------------------------------------------------
unsigned long int findGCD(unsigned long int a, unsigned long int b)
{
    unsigned long int c;
    while(1){
        c = a%b;
        if(c==0){return b;}
        a = b;
        b = c;
    }
    return 0;
}
//--------End find GCD function ----------------------------------------------

//--------Simple RSA function ------------------------------------------------
int ersa(int msg){
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
		if(findGCD(e,phi) == 1) break;
		else e++;
	}
	
	// generating private key
	//decrypt key d
	unsigned long int d;

	//k
	double k = 2;
	//double msg = 12; // length

	//ensure that the decryption key satifies the check
	d = (1+(k*phi))/e;
	double c = pow(msg,e);// encrypt the message with the encryption key
	c = fmod(c,n);
	//printf("%lf",c);
	return c;
}
//--------End RSA function ------------------------------------------------


//--------Task scheduler data structure---------------------------------------
// Struct for Tasks represent a running process in our simple real-time operating system.
typedef struct _task {
    /*Tasks should have members that include: state, period,
        a measurement of elapsed time, and a function pointer.*/
    signed char state; //Task's current state
    unsigned long int period; //Task period
    unsigned long int elapsedTime; //Time elapsed since last task tick
    int (*TickFct)(int); //Task tick function
} task;

//--------Shared Variables----------------------------------------------------
char keypadChar = 0;
char column = 9;
char newInput = 0;
char message = 0;
char encrypted[];
char count = 0;
char buffer[] = "        ";
//--------End Shared Variables------------------------------------------------


unsigned char GetKeypadKey() {

	PORTC = 0xEF; // Enable col 4 with 0, disable others with 1’s
	asm("nop"); // add a delay to allow PORTC to stabilize before checking
	if (GetBit(PINC,0)==0) { return('1'); }
	if (GetBit(PINC,1)==0) { return('4'); }
	if (GetBit(PINC,2)==0) { return('7'); }
	if (GetBit(PINC,3)==0) { return('*'); }

	// Check keys in col 2
	PORTC = 0xDF; // Enable col 5 with 0, disable others with 1’s
	asm("nop"); // add a delay to allow PORTC to stabilize before checking
	if (GetBit(PINC,0)==0) { return('2'); }
	if (GetBit(PINC,1)==0) { return('5'); }
	if (GetBit(PINC,2)==0) { return('8'); }
	if (GetBit(PINC,3)==0) { return('0'); }

	// Check keys in col 3
	PORTC = 0xBF; // Enable col 6 with 0, disable others with 1’s
	asm("nop"); // add a delay to allow PORTC to stabilize before checking
	if (GetBit(PINC,0)==0) { return('3'); }
	if (GetBit(PINC,1)==0) { return('6'); }
	if (GetBit(PINC,2)==0) { return('9'); }
	if (GetBit(PINC,3)==0) { return('#'); }

	// Check keys in col 4
	PORTC = 0x7F; // Enable col 7 with 0, disable others with 1’s
	asm("nop"); // add a delay to allow PORTC to stabilize before checking
	if (GetBit(PINC,0)==0) { return('A'); }
	if (GetBit(PINC,1)==0) { return('B'); }
	if (GetBit(PINC,2)==0) { return('C'); }
	if (GetBit(PINC,3)==0) { return('D'); }

	return('\0'); // default value

}

enum SM1_States { SM1_Start, SM1_wait, SM1_keypadPress};
	
int SMTick1(int state) {
	unsigned char keypadPress = GetKeypadKey();
	
	switch (state) {
		case SM1_Start:
			state = SM1_wait;
			break;
		case SM1_wait:
			if(keypadPress != '\0') {
				state = SM1_keypadPress;
			}
			break;
		
		case SM1_keypadPress:
			if(keypadPress == '\0') {
				state = SM1_wait;
			}else {
				state = SM1_keypadPress;				
			}
			break;
			
		default:
			state = SM1_wait;
			break;
	}
	
	switch (state) {
		case SM1_wait:
			break;
			
	case SM1_keypadPress:
		switch (keypadPress) {
			asm("nop");
			case '\0': newInput = 0; break;
			case '0': keypadChar = '0'; newInput = 1;break;
			case '1': keypadChar = '1'; newInput = 1;break; // hex equivalent
			case '2': keypadChar = '2'; newInput = 1;break;
			case '3': keypadChar = '3'; newInput = 1;break;
			case '4': keypadChar = '4'; newInput = 1;break;
			case '5': keypadChar = '5'; newInput = 1;break;
			case '6': keypadChar = '6'; newInput = 1;break;
			case '7': keypadChar = '7'; newInput = 1;break;
			case '8': keypadChar = '8'; newInput = 1;break;
			case '9': keypadChar = '9'; newInput = 1;break;
			case 'A': keypadChar = 'A'; newInput = 1;break;
			case 'B': keypadChar = 'B'; newInput = 1;break;
			case 'C': keypadChar = 'C'; newInput = 1;break; 
			case 'D': keypadChar = 'D'; newInput = 1;break;
			case '*': keypadChar = '*'; newInput = 0;break;
			case '#': keypadChar = '#'; newInput = 0;break;
			default: keypadChar = 0x20; break; // Should never occur.
		}
		break;
			
		default:
			break;
		}
	return state;
}
	
	enum SM2_States { SM2_Start, SM2_Display };
		
	int SMTick2 (int state) {
		switch (state) {
			case SM2_Start:
				state = SM2_Display;
				break;
				
			case SM2_Display:
			break;
			
			default:
				state = SM2_Display;
				break;
		}
		
		switch (state) {
			case SM2_Start:		
				break;
			
			case SM2_Display:
				if(newInput != 0) {
					if(column < 17) {
						asm("nop");
						LCD_Cursor(column);
						if(keypadChar) {
							LCD_WriteData(keypadChar);
							message += keypadChar;
							column++;
						}
						newInput = 0;
						asm("nop");
						break;
					}
					else {
						column = 9;
						count = 0;
						LCD_Cursor(column);
						if(keypadChar) {
							LCD_WriteData(keypadChar);
							message = keypadChar;
							column++;
						}
						
						newInput = 0;
						asm("nop");
						break;
					}
				}
				break;
				
				default:
					break;
		}
	return state;
}
char msg_len = 0;
char check = 0;
enum SM3_States { SM3_Start, SM3_Encrypt, SM3_Release, SM3_Display };
unsigned char tmpB = 0x00;
int SMTick3(int state) {
	switch (state) {
		case SM3_Start:
			state = SM3_Encrypt;
		break;
		
		case SM3_Encrypt:
			tmpB = ~PINA & 0x04;
			if(tmpB) {
				state = SM3_Release;
				break;
			}
			else {
				state = SM3_Encrypt;
				break;
			}
			break;
			
		case SM3_Release:
			tmpB = ~PINA & 0x04;
			if(tmpB) {
				 state = SM3_Release;
				 break;
			}
			else {
				msg_len = strlen(message);
				if(msg_len == 0) {
					check = 0;
					break;
				}
				else {
					state = SM3_Display;
					check = 1;
					break;
				}
			}
			break;
		
		case SM3_Display:
			break;
		break;
		
		default:
		state = SM3_Encrypt;
		break;
	}
	
	switch (state) {
		case SM3_Start:
			break;
		
		case SM3_Encrypt:
			
			encrypted[50] = ersa(message);
			break;
		
		case SM3_Display:
			if(check != 0) {
				char encrypt[] = "Encrypted Value: ";
				strcat(encrypt, encrypted);
				LCD_DisplayString(1, encrypt);
			}
			break;
		
		default: 
			break;
	}
	return state;
}


// enum SM4_States { SM4_Start, SM4_Begin, SM4_Message, SM4_End};
// int SMTick4(int state) {
// 	switch (state) {
// 		case SM4_Start:
// 			state = SM4_Begin;
// 			break;
// 		
// 		case SM4_Begin:
// 		break;
// 			
// 	}
// 	};

int main(void)
{
// Set Data Direction Registers
DDRA = 0xFF; PORTA = 0x00; // LCD control lines
DDRC = 0xF0; PORTC = 0x0F; // Keypad
DDRD = 0xFF; PORTD = 0x00; // LCD data lines
DDRB = 0xFF; PORTB = 0x00; // Xbee Data lines
// Period for the tasks
unsigned long int SMTick1_calc = 50;
unsigned long int SMTick2_calc = 500;
unsigned long int SMTick3_calc = 500;
/*unsigned long int SMTick4_calc = 10;*/

// Calculating GCD
unsigned long int tmpGCD = 1;
tmpGCD = findGCD (SMTick1_calc, SMTick2_calc);
tmpGCD = findGCD(tmpGCD, SMTick3_calc);
/*tmpGCD = findGCD(tmpGCD, SMTick4_calc);*/
// Greatest common divisor for all tasks or smallest time unit for tasks
unsigned long int GCD = tmpGCD;

//Recalculate GCD periods for scheduler
unsigned long int SMTick1_period = SMTick1_calc / GCD;
unsigned long int SMTick2_period = SMTick2_calc / GCD;
unsigned long int SMTick3_period = SMTick3_calc / GCD;
/*unsigned long int SMTick4_period = SMTick4_calc / GCD;*/

// Declare an array of tasks
static task task1, task2, task3;//, task4;
task *tasks[] = { &task1, &task2, &task3};//, &task4 };
const unsigned short numTasks = sizeof(tasks) / sizeof(task*);

// Task 1
task1.state = -1; // Task initial state.
task1.period = SMTick1_period; // Task Period.
task1.elapsedTime = SMTick1_period; // Task current elapsed time.
task1.TickFct = &SMTick1; // Function pointer for the tick.

//Task 2
LCD_init();
task2.state = -1; // Task initial state.
task2.period = SMTick2_period; // Task Period.
task2.elapsedTime = SMTick2_period; // Task current elapsed time.
task2.TickFct = &SMTick2; // Function pointer for the tick.

// Task 3
task3.state = -1;//Task initial state.
task3.period = SMTick3_period;//Task Period.
task3.elapsedTime = SMTick3_period; // Task current elasped time.
task3.TickFct = &SMTick3; // Function pointer for the tick.

// Task 4
// task4.state = -1;//Task initial state.
// task4.period = SMTick3_period;//Task Period.
// task4.elapsedTime = SMTick4_period; // Task current elasped time.
// task4.TickFct = &SMTick4; // Function pointer for the tick.

// Set the timer and turn it on
TimerSet(GCD);
TimerOn();
char MSG[] = "Message:";
//const char length_msg = strlen(MSG);
char test[] = "testing";
//strcat(MSG, buffer);
strcat(MSG, test);
LCD_DisplayString(1, MSG);

//const char MSG[] = "Woomy!";

//LCD_WriteData(test);
//LCD_DisplayString(17, MSG);
//LCD_DisplayString(17,"testing:");
unsigned short i; // Scheduler for-loop iterator
while(1)
{
	// Scheduler code
	for ( i = 0; i < numTasks; i++ )
	{
		// Task is ready to tick
		if ( tasks[i]->elapsedTime == tasks[i]->period )
		{
			// Setting next state for task
			tasks[i]->state = tasks[i]->TickFct(tasks[i]->state);
			// Reset the elapsed time for next tick.
			tasks[i]->elapsedTime = 0;
		}
		tasks[i]->elapsedTime += 1;
	}
	while(!TimerFlag);
	TimerFlag = 0;
}

// Error: Program should not exit!
return 0;
}

