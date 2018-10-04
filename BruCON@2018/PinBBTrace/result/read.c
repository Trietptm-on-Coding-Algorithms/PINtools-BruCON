#include <stdio.h>

void help() { 
  printf("this program requires filepath as input\n"); 
  exit(1); 
} 

void print_error_exit(char *msg) { 
  printf(msg); 
  exit(2); 
} 

int main(int argc, char** argv) {

  FILE *fp ; 
  int number; 
  
  if (argc == 2) {
    fp = fopen(argv[1], "rb"); 
    if (!fp) 
      print_error_exit("no file opened, path does not exists\n"); 
      
    fscanf(fp, "%d", &number);
    if(number == 100)
      printf("you've got it right\n"); 
    else
      print_error_exit("not successful!, try again.\n");
      
    fclose(fp);
  } 
  else { 
    help(); 
  }
  return 0; 
  
} 
