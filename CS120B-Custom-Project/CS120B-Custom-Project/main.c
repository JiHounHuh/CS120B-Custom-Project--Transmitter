/*  Name & E-mail: Ji Houn Huh (jhuh009@ucr.edu)
 *  Lab Section: 23
 *  Assignment: Custom Project
 *  Project Description: Transmit encrypted message 
 *  
 *  I acknowledge all content contained herein, excluding template or example
 *  code, is my own original work.
 */

#include <avr/io.h>
#include <avr/interrupt.h>
#include "bit.h"
#include "io.c"
#include "timer.h"
#include "stdio.h"

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
char column = 1;
char newInput = 0;
//--------End Shared Variables------------------------------------------------

//--------End Task scheduler data structure-----------------------------------

//--------Shared Functions----------------------------------------------------
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

//--------End Shared Functions------------------------------------------------

//--------User defined FSMs---------------------------------------------------

//Enumeration of states.
enum SM1_States { SM1_Start, SM1_wait, SM1_keypadPress };

int SMTick1(int state)
{
    // Local Variables
    unsigned char keypadPress = GetKeypadKey();
    
    //State machine transitions
    switch (state) {
    case SM1_Start:
        state = SM1_wait;
        break;
        
    case SM1_wait:
        if(keypadPress != '\0'){
            state = SM1_keypadPress;
        }   
        break;

    case SM1_keypadPress:   
        if(keypadPress == '\0'){
            state = SM1_wait;
        }else{
            state = SM1_keypadPress;
        }
        break;
        
    default:        
        state = SM1_wait; // default: Initial state
        break;
    }

    //State machine actions
    switch(state) {
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
                case '*': keypadChar = '*'; newInput = 1;break;
                case '#': keypadChar = '#'; newInput = 1;break;
                default: keypadChar = 0x20; break; // Should never occur.
            }
            break;

        default:        
    break;
    }

    return state;
}

// Enumeration of states.
enum SM2_States { SM2_Start, SM2_Display };

int SMTick2(int state)
{
    switch (state)
    {
        case SM2_Start:
        state = SM2_Display;
        break;
        
        case SM2_Display:
        //state = SM2_Display;
        break;
        
        default:
        state = SM2_Display;
        break;
    }
    
    switch (state)
    {
        case SM2_Start:
            break;
        
        case SM2_Display:
			if(newInput != 0){
				if(column < 17){
					asm("nop");
					LCD_Cursor(column);
					if (keypadChar)
					{
						LCD_WriteData(keypadChar);
					}
					column++;
					newInput = 0;
					asm("nop");
					break;
				}
				else {
					column = 1;
					LCD_Cursor(column);
					if (keypadChar)
					{
						LCD_WriteData(keypadChar);
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

// Implement scheduler code from PES.
int main()
{
    // Set Data Direction Registers
    DDRA = 0xFF; PORTA = 0x00; // LCD control lines
    DDRC = 0xF0; PORTC = 0x0F; // Keypad
    DDRD = 0xFF; PORTD = 0x00; // LCD data lines

    // Period for the tasks
    unsigned long int SMTick1_calc = 50;
    unsigned long int SMTick2_calc = 500;

    // Calculating GCD
    unsigned long int tmpGCD = 1;
    tmpGCD = findGCD (SMTick1_calc, SMTick2_calc);

    // Greatest common divisor for all tasks or smallest time unit for tasks
    unsigned long int GCD = tmpGCD;

    //Recalculate GCD periods for scheduler
    unsigned long int SMTick1_period = SMTick1_calc / GCD;
    unsigned long int SMTick2_period = SMTick2_calc / GCD;

    // Declare an array of tasks 
    static task task1, task2;
    task *tasks[] = { &task1, &task2 };
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

    // Set the timer and turn it on
    TimerSet(GCD);
    TimerOn();

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
