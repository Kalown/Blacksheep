```plaintext
                                             .   .  .                                               
     .                                                               .                .             
                           ..                                          . .                 .        
      .          .                             .         .         .       .                    .   
     .       .                                           ..  .        .      .                       
              .       .    .       .      .                                                         
   .                   .                                       ..  .        .      .                
         . .                      .                     ....     ....                               
      .                                                 ....     ...   .                             
          .  .          .          .      .      ...+##*+++*%%+=##++#+..                    .       
                        ..                      ..*#+-*-#=*-=-+%@@@*-**.     .                       
                                       . .  ....:%*-*%@@@@@@##==@%%%#+%.. ..   .   .               .
      .                                 .   .. .##=#@@@@@@@@@%%-.....-@:....                    
                           .       .        . .:@=#@@@*#.+-=%+.:=-... *@%%..                        
                                            ....@=+@@%.-#*+*#..#@#:....=@-..                        
   .  .                     .. . ....  . . .....*%:+@@#+#@@@@...::-.... :#=.  ..                    
                            ...... ......... .. .*%=-*##*+@@# . . ..    ..**.. .                    
     .     .        . . ......-+*++%@%*#%*=+*--=-:*@@*++#@@@%....... ...++=@:.      .     .         
                    . . ..-@@@@%%#%#==+#**%@@@@@@@@%%@%@@**-@#........::.-%%..   .               
                    . ..=#@@%:...........:-...*=.....=-:#...:+@@%@@@@%*-=#@#..         .            
                    . +@@*:.....  .         ....    ........:***%@@@@*:-=-:#@%*:....                
      .           . .:@@++-... .          . ...     .:+.....+-=%@@@@@-...  *%##*=-..   .   .      . 
                    -@@%%-..                 .      ..*+..==:#%#@@@@@+ .. .##+**+...        . .     
                    *@@@-...       .        .        ..+%-.=%*+@@@@@%.....=-*:%:+*..                
                  ..*@@*--.  . ..-...... .  ..:.    .:- .#@*:=@@@@@@@: .....*.*- ==         .       
 .              ..:%@@@*#... .=.*=.+. .......#... ....:#+.:*@@@@@@@@=..  . .:.+-..:.                
  .       .     ..%@@@@@=:. .-%:@=.#..-. :*.*#......+...+@%**%@@@@@@-....  .. :. . .                
         .      ..%@#@@#+=...+@+@#.@-.#..+%.%@...:-.:##=--+%@@@@@@@+....    ....                    
                . ..:@@+@-.*.-@@@@=#%:#*.+@=#@*.*:=*-:*@@@@@@@@@@@%-.. .    . .. ..                  
                    -@@@@+.@=%@@@@@*@@+@%-@@%@@+-%+:%@#+%@@@@@@@@@-.....    ...-.. .     .          
       .            .:@@@@:%@@@@@@@@@@@@@@@@@@@@%-@@@%@@@@@@@@@@%=...... .  .#@:   .     .          
                    .:@@@@@*@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@@@%:.... :%:..=@@-.....                
            .       ..:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*... .....#@-.%@+.-=:..                
#      .            ...=@@@@@@@%+@@@@@@@@%@@@@@@@@@@@@@@@@%+:.  ...:+-..+@%-+.:*+....                
#                    :#@@@@@@%=.-@@@@@@#:.:-:.-=-%@@@@@@@@- . .......**..=*#.-@+.. ..  .              
#                    =@@@@@*.. =@@@@@%:.   .   . *@@@#@@@@:. .  ......*#..%-=@+....:-..               
# .    .   .          =@@@+.....#@@@@-....      . +@@@+%@@@:...  .:-+#*-@+:*-@#..=%=.....    .        
#                    -@@@.. .  =@@@-. ..    .    -@@@-*@@%. .. ...-:.:*@@-:%@::#%:.--....            
#   .                -@@%.. ....@@@=.            .%@#.:@@=.........=#-.*@+*@+:%%-*#-.....          . 
#                    -@@%.. ... *@@*.. . . .  . ..%@#.:@@= ... .-++--@=-@%@@:%@*@*.   . .            
#             .      -@@#..:....-@@%.. ...........%@#.:@@= .....:-.+%%@:@@@#=@@@*...                   
#    .               +@@%...#:+..%@@-..=-=..:*==..@@%.-@@*...*..=-#.+@@=%@@+%@@%.  ..                
#      .    .. ......-@%%#.:+%-%.#@@@==*.%=.@=:@:-@@@+=@@@=.%=-:#:##:@@*%@@=@@@=. ...                
#   .         ...=+*#%@%#@%%=@+@#@@#%@@**%@#@++@%#@*%@%@*%@+@+@*@@@@+%@#%@@+@@@%#*+-.                
#            ...:*#%@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#*:                
#            .........:-=+*##%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%##*+=-:.....       .    .    
#                          .             ...................      .     .                 .         .
#                    .             .     .. .. ............ .                                 .      
#                               .              ..               ..                       .           
#        .                   .                                .                      .   .           
#                  .                   .                        .           .              .        .
# .                                          .  .  .                .  .              .         .    
#    .       .          .                                                 .             .     .     .
#      .                  .            .            .    .                 .                   .     
#             .  .           .       .          .                    .  
```




# **BlackSheep**

BlackSheep allows users to scan a specified directory of files, compute their MD5 hash values, and check these hashes against the **VirusTotal** API to determine whether they are potentially malicious. It provides a simple, user-friendly graphical interface (GUI) built with Python's `Tkinter` library, making it accessible even for non-technical users.

## **Requirements**

To run this tool, ensure you have the following Python libraries installed:

- **Python 3.6+** (for compatibility with the libraries used and general performance).
- **requests** (to communicate with the VirusTotal API).
- **Tkinter** (Python’s standard GUI library; should come pre-installed with Python).

### Install the required libraries:

1. **Install Requests**:
   ```bash
   pip install requests
   ```

2. **Install Tkinter**:
   - **Windows**: Tkinter comes pre-installed with Python on Windows. You don’t need to install it separately.
   - **Debian/Ubuntu**:
     If you're using Linux (Debian/Ubuntu), you may need to install Tkinter manually. Run the following command:
     ```bash
     sudo apt-get install python3-tk
     ```

### Set up the **VirusTotal API Key**:
- To use the tool, you will need a **VirusTotal API key**. You can get your API key by registering at [VirusTotal](https://www.virustotal.com/).
- Paste your API key into the input field in the GUI.

---

