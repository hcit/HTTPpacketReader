
#ifdef _colours

#include <stdio.h>  

#define COLOUR_RED "\e[31m"  
#define COLOUR_B_RED "\e[31;1m"  
#define COLOUR_GREEN "\e[32m"  
#define COLOUR_B_GREEN "\e[32;1m"  
#define COLOUR_YELLOW "\e[33m"  
#define COLOUR_B_YELLOW "\e[33;1m"  
#define COLOUR_BLUE "\e[34m"  
#define COLOUR_B_BLUE "\e[34;1m"  
#define COLOUR_MAGENTA "\e[35m"  
#define COLOUR_BRIGHT "\e[1m"  
#define COLOUR_CYAN "\e[36m"  
#define COLOUR_NONE "\e[m"  

#endif

#ifndef _colours

#define COLOUR_RED ""  
#define COLOUR_B_RED ""  
#define COLOUR_GREEN ""  
#define COLOUR_B_GREEN ""  
#define COLOUR_YELLOW ""  
#define COLOUR_B_YELLOW ""  
#define COLOUR_BLUE ""  
#define COLOUR_B_BLUE ""    
#define COLOUR_MAGENTA ""    
#define COLOUR_BRIGHT ""    
#define COLOUR_CYAN ""  
#define COLOUR_NONE ""  

#endif