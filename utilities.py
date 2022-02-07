"""
-----------------------------
Name: Torin Borton-McCallum
Description: Utilitites File for Ciphers
-----------------------------
"""

SCHAR = "-!@#$%^&*<>\.,():;\"'{[]}+_=)" #list of special characters
B6 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ \n" #B6 code characters
DICT_FILE = 'engmix.txt'
ASSERTION = 'invalid input'
PAD = 'q'

def debug(ciphertext, size = 200):
    """
    ----------------------------------------------------
    Parameters:   ciphertext (str)
                  size (int): max characters to display in debug console
    Return:       -
    Description:  Debugging tool for Simple Substitution Cipher
                  Supports two commands:
                      replace <char1> with <char2>
                      end
    ---------------------------------------------------
    """
    base_str = 'abcdefghijklmnopqrstuvwxyz ,;-:?.'
    sub_str = ['-' for _ in range(len(base_str))]
    
    _ = get_positions(ciphertext,'\n')
    ciphertext = clean_text(ciphertext,'\n')
    
    plaintext = ['-' for i in range(len(ciphertext))]
    print('Ciphertext:')
    print(ciphertext[:size])
    print()
    command = input('Debug Mode: Enter Command: ')
    input('Description: ')
    print()
    
    while command != 'end':
        sub_char = command[8].lower()
        base_char  = command[15].lower()
            
        if base_char in base_str:
            indx = base_str.index(base_char)
            sub_str[indx] = sub_char
        else:
            print('(Error): Base Character does not exist!\n')

        print('Base:',end='')
        for i in range(len(base_str)):
            print('{} '.format(base_str[i]),end='')
        print()
        print('Sub :',end='')
        for i in range(len(sub_str)):
            print('{} '.format(sub_str[i]),end='')
        print('\n')

        print('ciphertext:')
        print(ciphertext[:size])
        for i in range(len(plaintext)):
            if ciphertext[i].lower() == sub_char:
                plaintext[i] = base_char
        print('plaintext :')
        print("".join(plaintext[:size]))
        print('\n_______________________________________\n')
        command = input('Enter Command: ')
        if command != 'end':
            input('Description: ')
        print()
    return
    
'______________________________________________________________________________'

def get_base(base_type):
    """
    ---------------------------------------------------- 
    Parameters:   base_type (str) 
    Return:       result (str)
    Description:  Return a base string containing a subset of ASCII charactes
                  Defined base types:
                  lower, upper, alpha, lowernum, uppernum, alphanum, special, nonalpha, B6, BA, all
                      lower: lower case characters
                      upper: upper case characters
                      alpha: upper and lower case characters
                      lowernum: lower case and numerical characters
                      uppernum: upper case and numerical characters
                      alphanum: upper, lower and numerical characters
                      special: punctuations and special characters (no white space)
                      nonalpha: special and numerical characters
                      B6: num, lower, upper, space and newline
                      BA: upper + lower + num + special + ' \n'
                      all: upper, lower, numerical and special characters
    Errors:       if invalid base type, print error msg, return empty string
    ---------------------------------------------------
    """
    lower = "".join([chr(ord('a')+i) for i in range(26)])
    upper = lower.upper()
    num = "".join([str(i) for i in range(10)])
    special = ''
    for i in range(ord('!'),127):
        if not chr(i).isalnum():
            special+= chr(i)
            
    result = ''
    if base_type == 'lower':
        result = lower
    elif base_type == 'upper':
        result = upper
    elif base_type == 'alpha':
        result = upper + lower
    elif base_type == 'lowernum':
        result = lower + num
    elif base_type == 'uppernum':
        result = upper + num
    elif base_type == 'alphanum':
        result = upper + lower + num
    elif base_type == 'special':
        result = special
    elif base_type == 'nonalpha':
        result = special + num
    elif base_type == 'B6': #64 symbols
        result = num + lower + upper + ' ' + '\n'
    elif base_type == 'BA': #96 symbols
        result = upper + lower + num + special + ' \n'
    elif base_type == 'all':
        result = upper + lower + num + special
    else:
        print('Error(get_base): undefined base type')
        result = ''
    return result

'______________________________________________________________________________'

def get_language_freq(language='English'):
    """
    ----------------------------------------------------
    Parameters:   language (str): default = English 
    Return:       freq (list of floats) 
    Description:  Return frequencies of characters in a given language
                  Current implementation supports English language
                  If unsupported language --> print error msg and return []
    ---------------------------------------------------
    """
    if language == 'English':
        return [0.08167,0.01492,0.02782, 0.04253, 0.12702,0.02228, 0.02015,
                0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                0.00978, 0.0236, 0.0015, 0.01974, 0.00074]
    else:
        print('Error(get_language_freq): unsupported language')
        return []
    
'______________________________________________________________________________'

def file_to_text(filename):
    """
    ----------------------------------------------------
    Parameters:   filename (str)
    Return:       contents (str)
    Description:  Utility function to read contents of a file
                  Can be used to read plaintext or ciphertext
    Asserts:      filename is a valid name
    ---------------------------------------------------
    """
    assert is_valid_filename(filename), ASSERTION; #assertion check valid file name
    
    file = open(filename, "r"); #open file with read permissions
    contents = file.read(); #read contents of file to return variable
    
    return contents;

'______________________________________________________________________________'

def text_to_file(text, filename):
    """
    ----------------------------------------------------
    Parameters:   text (str)
                  filename (str)            
    Return:       no returns
    Description:  Utility function to write any given text to a file
                  If file already exist, previous contents will be erased
    Asserts:      text is a string and filename is a valid filename
    ---------------------------------------------------
    """
    assert is_valid_filename(filename), ASSERTION; #assertion check valid file name
    assert type(text) == str, ASSERTION; #assertion check valid file name
    
    file = open(filename, "w");#open file with write permissions
    file.write(text);#write contents of string to file
    return;

'______________________________________________________________________________'

def is_valid_filename(filename):
    """
    ----------------------------------------------------
    Parameters:   filename (str)
    Return:       True/False
    Description:  Checks if given input is a valid filename 
                  a filename should have at least 3 characters
                  and contains a single dot that is not the first or last character
    ---------------------------------------------------
    """
    filename_count = 0;
    i = 0;
    extension = False;
    is_valid = True

    #if filename.length is less than 4, xxx.c, then false 
    #if '.' is greater than 2, false.
    if len(filename) > 4 and filename.count('.') == 1:
            
        while (i < len(filename) and is_valid is True):
            
            char = filename[i];
            
            if extension == False:
                
                #increment the count for the length of the filename
                
                #checking for alphanumeric
                if char.isalnum() or char == "_":
                    filename_count+=1;
                                
                elif char == "." and filename_count <= 3:
                    is_valid = False;
                    extension = True;
            
            i+=1
            
        #check that it ends with a proper end
        ext = (".py", ".c", ".txt")
        if filename.endswith(ext) == False:
            is_valid = False
        
        #check that it doesnt start with .
        if filename.startswith('.') == True:
            is_valid = False
            
    else:
        is_valid = False
      
    return is_valid;

'______________________________________________________________________________'
   
def load_dictionary(dict_file=None):
    """
    ----------------------------------------------------
    Parameters:   dict_file (str): filename
                        default value = None
    Return:       dict_list (list): 2D list
    Description:  Reads a given dictionary file
                  dictionary is assumed to be formatted as each word in a separate line
                  Returns a list of lists, list 0 contains all words starting with 'a'
                  list 1 all words starting with 'b' and so forth.
                  if no parameter given, use default file (DICT_FILE)
    Errors:       if invalid filename, print error msg, return []
    Notes: For the function load_dictionary when opening the dictionary files use encoding="ISO-8859-15"
    ---------------------------------------------------
    """
    if (is_valid_filename(dict_file) == False):#if invalid filename, print error msg, return []
        print('Error(<function_name): <error_msg>') 
        dict_list = [];
    else:
        file = open(dict_file, "r", encoding="ISO-8859-15"); #open file with read permissions
        dict_list = [[] for _ in range(26)]#make a dictionary with space for each letter
        for word in file:
            key = ord(word[0]) - 97;#sort words by letter so index lines up w list. Example: 'a' is given the value 0 (ASCII val = 97)
            dict_list[key].append(word.strip());#add the word to dictionary and strip whitespaces
    
    return dict_list;

'______________________________________________________________________________'

def text_to_words(text):
    """
    ----------------------------------------------------
    Parameters:   text (str)
    Return:       word_list (list)
    Description:  Reads a given text
                  Returns a list of strings, each pertaining to a word in the text
                  Words are separated by a white space (space, tab or newline)
                  Gets rid of all special characters at the start and at the end
    Asserts:      text is a string
    ---------------------------------------------------
    """
    assert type(text) == str
    word_list = text.split();#split words into a list by removing all whitespaces
    
    for i in range(len(word_list)):#go through each word in list
        word_list[i] = (word_list[i].strip(SCHAR))#strip hyphens so only hyphens inbetween text will be safe
    
    return word_list
'______________________________________________________________________________'

def analyze_text(text, dict_list):
    """
    ----------------------------------------------------
    Parameters:   text (str)
                  dict_list (list)
    Return:       matches (int)
                  mismatches (int)
    Description:  Reads a given text, checks if each word appears in given dictionary
                  Returns number of matches and mismatches.
                  Words are compared in lowercase
                  Assumes a proper dict_list
    Asserts:      text is a string and dict_list is a list
    ---------------------------------------------------
    """
    assert type(dict_list) == list, ASSERTION; #assertion check valid file name
    assert type(text) == str, ASSERTION; #assertion check valid file name
    
    matches = 0; #return variables for number of matches and mismatches
    mismatches = 0;
    
    index = 0 #represents the first letter of each word to search in the dictionary
    mylist = text_to_words(text); #convert given text into a list of words
    
    for word in mylist:#for each word in the created lsit
        if word == "": # if theres a blank line its a mismatch
            mismatches += 1;
        else:
            index = ord(word[0].lower()) - 97 #find the index of the first letter
            if (index > 26 or index < 0): #if its not a letter its a mismatch
                mismatches += 1;
                continue;#dont run the next if statement
            if (word.lower() in dict_list[index]):#if word in dictionary increase matches
                matches += 1;
            else: mismatches += 1;#otherwise increase mismatches
            
    return matches, mismatches;     
            

'______________________________________________________________________________'

def is_plaintext(text, dict_list, threshold=0.9):
    """
    ----------------------------------------------------
    Parameters:   text (str)
                  dict_list (list): dictionary list
                  threshold (float): number between 0 to 1
                      default value = 0.9
    Return:       True/False
    Description:  Check if a given file is a plaintext
                  If #matches/#words >= threshold --> True
                      otherwise --> False
                  If invalid threshold, set to default value of 0.9
                  An empty text should return False
                  Assumes a valid dict_list is passed
    ---------------------------------------------------
    """
    myvalue = True
    matches = analyze_text(text, dict_list)[0];
    word_count = len(text_to_words(text));
    
    if text == "" or matches/word_count < threshold:
        myvalue = False
    return myvalue
        

'______________________________________________________________________________'

def new_matrix(r,c,fill):
    """
    ----------------------------------------------------
    Parameters:   r: #rows (int)
                  c: #columns (int)
                  fill (str,int,double)
    Return:       matrix (2D List)
    Description:  Create an empty matrix of size r x c
                  All elements initialized to fill
                  minimum #rows and #columns = 2
                  If invalid value given, set to 2
    ---------------------------------------------------
    """
    if r < 2: r = 2;
    if c < 2: c = 2;
    matrix = [[fill for _ in range(c)] for _ in range(r)]
    return matrix

'______________________________________________________________________________'

def print_matrix(matrix):
    """
    ----------------------------------------------------
    Parameters:   matrix (2D List)
    Return:       -
    Description:  prints a matrix each row in a separate line
                  items separated by a tab
                  Assumes given parameter is a valid matrix
    ---------------------------------------------------
    """    
    for i in range(len(matrix)):
        
        for j in matrix[i]:
            print('{}'.format(j), end='\t')
    
        print()
    
    return None

'______________________________________________________________________________'

def index_2d(input_list,item):
    """
    ----------------------------------------------------
    Parameters:   input_list (list): 2D list
                  item (?)
    Return:       i (int): row number
                  j (int): column number
    Description:  Performs linear search on input list to find "item"
                  returns i,j, where i is the row number and j is the column number
                  if not found returns -1,-1
    Asserts:      input_list is a list
    ---------------------------------------------------
    """
    assert type(input_list) == list, ASSERTION; #assertion check valid file name
    
    found = False;
    for i in range(len(input_list)):
        for j in range(len(input_list[i])):
            
            if (input_list[i][j] == item):
                found = True;
                break;
                
        if found == True: break
                   
    if found is False:
        i = j = -1;
    return i, j
'______________________________________________________________________________'

def shift_string(text,s,d='l'):
    """
    ----------------------------------------------------
    Parameters:   text (string): input string
                  s - shifts (int): number of shifts
                  d - direction (str): 'l' or 'r'
    Return:       update_text (str)
    Description:  Shift a given string by given number of shifts (circular shift)
                  If shifts is a negative value, direction is changed
                  If no direction is given or if it is not 'l' or 'r' set to 'l'
    Asserts:      text is a string and shifts is an integer
    ---------------------------------------------------
    """
    assert type(text) == str, ASSERTION; #assertion check valid file name
    assert type(s) == int, ASSERTION; #assertion check valid file name
    
    update_text = ""
    if d == 'r':
        s = s*-1
    for i in range(len(text)):
        key = (s+i)%(len(text));
        update_text += text[key]

    return update_text

'______________________________________________________________________________'

def matrix_to_string(matrix):
    """
    ----------------------------------------------------
    Parameters:   matrix (2D List)
    Return:       text (string)
    Description:  convert a 2D list of characters to a string
                  from top-left to right-bottom
                  Assumes given matrix is a valid 2D character list
    ---------------------------------------------------
    """
    text = ""
    for row in matrix:
        
        for word in row:
            text += word;
    
    
    return text

'______________________________________________________________________________'

def get_positions(text,base):
    """
    ----------------------------------------------------
    Parameters:   text (str): input string
                  base (str):  stream of unique characters
    Return:       positions (2D list)
    Description:  Analyzes a given text for any occurrence of base characters
                  Returns a 2D list with characters and their respective positions
                  format: [[char1,pos1], [char2,pos2],...]
                  Example: get_positions('I have 3 cents.','c.h') -->
                      [['h',2],['c',9],['.',14]]
                  items are ordered based on their occurrence in the text
    Asserts:      text and base are strings
    ---------------------------------------------------
    """
    assert type(text) == str, ASSERTION; #assertion check valid file name
    assert type(base) == str, ASSERTION; #assertion check valid file name
    
    positions = []
    i = -1;
    for letter in text:
        i += 1;
        if letter not in base:
            continue;
        else:
            temp = []
            temp.append(letter)
            temp.append(i)
            positions.append(temp)
            

    return positions

'______________________________________________________________________________'

def clean_text(text,base):
    """
    ----------------------------------------------------
    Parameters:   text (str)
                  base (str)
    Return:       updated_text (str)
    Description:  Constructs and returns a new text which has
                  all characters in original text after removing base characters
    Asserts:      text and base are strings
    ---------------------------------------------------
    """
    assert type(text) == str, ASSERTION; #assertion check valid file name
    assert type(base) == str, ASSERTION; #assertion check valid file name
    
    updated_text = "";
    
    i = -1;
    for letter in text:
        i += 1;
        if letter not in base:
            updated_text += letter
    
    return updated_text

'______________________________________________________________________________'

def insert_positions(text, positions):
    """
    ----------------------------------------------------
    Parameters:   text (str)
                  positions (list): [[char1,pos1],[char2,pos2],...]]
    Return:       updated_text (str)
    Description:  Inserts all characters in the positions 2D list (generated by get_positions)
                  into their respective locations
                  Assumes a valid positions 2d list is given
    Asserts:      text is a string and positions is a list
    ---------------------------------------------------
    """
    assert type(text) == str, ASSERTION; #assertion check valid file name
    assert type(positions) == list, ASSERTION; #assertion check valid file name
    
    updated_text = "";
    
    i = 0;
    j = 0;
    for item in positions:
        while(item[1] != i):
            updated_text += text[j]
            j+=1
            i+=1
        updated_text += item[0];
        i+=1
    while j < len(text):
        updated_text+= text[j]
        j+=1

    
    return updated_text

'______________________________________________________________________________'

def text_to_blocks(text,b_size,padding = False,pad =PAD):
    """
    ----------------------------------------------------
    Parameters:   text (str): input string
                  b_size (int)
                  padding (bool): False(default) = no padding, True = padding
                  pad (str): padding character, default = PAD
    Return:       blocks (list)
    Description:  Create a list containing strings each of given block size
                  if padding flag is set, pad empty blocks using given padding character
                  if no padding character given, use global PAD
    Asserts:      text is a string and block_size is a positive integer
    ---------------------------------------------------
    """
    assert type(text) == str, ASSERTION; #assertion check valid file name
    assert type(b_size) == int and b_size >0, ASSERTION; #assertion check valid file name
    i = 0;
    blocks = []
    temp = ""
    for i in range(len(text)):

        if ((i+1)%b_size == 0 and i > 0):
            temp+= text[i]
            blocks.append(temp)
            temp = ""
        else:
            temp+= text[i]
            
    if(len(temp) > 0):
        if padding == True:
            while len(temp)<b_size:
                temp+=pad
        blocks.append(temp)
            
        
    return blocks

'______________________________________________________________________________'

def blocks_to_baskets(blocks):
    """
    ----------------------------------------------------
    Parameters:   blocks (list): list of equal size strings
    Return:       baskets: (list): list of equal size strings
    Description:  Create k baskets, where k = block_size
                  basket[i] contains the ith character from each block
    Errors:       if blocks are not strings or are of different sizes -->
                    print 'Error(blocks_to_baskets): invalid blocks', return []
    ----------------------------------------------------
    """
    size = len(str(blocks[0]))
    
    baskets = ["" for _ in range(size)]
           
    
    for word in blocks:
        if type(blocks) != list or type(word) != str or len(word) != size:
            print("Error(blocks_to_baskets): invalid blocks")
            baskets = []
            break;
        else:
            for i in range(size):
                baskets[i] += word[i]
    return baskets            

'______________________________________________________________________________'

def compare_texts(text1,text2):
    """
    ----------------------------------------------------
    Parameters:   text1 (str)
                  text2 (str)
    Return:       matches (int)
    Description:  Compares two strings and returns number of matches
                  Comparison is done over character by character
    Assert:       text1 and text2 are strings
    ----------------------------------------------------
    """
    assert type(text1) == type(text2) == str
    length = 0;
    matches = 0;
    
    if len(text1) < len(text2):
        length = len(text1);
    else: length = len(text2);
    
    for i in range(length):
        if text1[i] == text2[i]:
            matches +=1;
        
    return matches

'______________________________________________________________________________'

def get_freq(text,base = ''):
    """
    ----------------------------------------------------
    Parameters:   text (str)
                  base (str): default = ''
    Return:       count_list (list of floats) 
    Description:  Finds character frequencies (count) in a given text
                  Default is English language (counts both upper and lower case)
                  Otherwise returns frequencies of characters defined in base
    Assert:       text is a string
    ----------------------------------------------------
    """
    count_list = []
    assert type(text) == str , ASSERTION
    if base == None: 
        count_list = [text.count(chr(97+i))+text.count(chr(65+i)) for i in range(26)]
    else:
        count_list = [text.count(char) for char in base]
    return count_list


'______________________________________________________________________________'

def is_binary(b):
    """
    ----------------------------------------------------
    Parameters:   b (str): binary number
    Return:       True/False
    Description:  Checks if given input is a string that represent a valid
                  binary number
                  An empty string, or a string that contains other than 0 or 1
                  should return False
    ---------------------------------------------------
    """
    my_val = True;
    
    if(type(b) is not str or b.isdigit() is False):
        my_val = False
    if my_val == True:
        for bit in b:
            if int(bit) >1 or int(bit) < 0:
                my_val = False;
                break;
    return my_val;
'______________________________________________________________________________'

def bin_to_dec(b):
    """
    ----------------------------------------------------
    Parameters:   b (str): binary number
    Return:       decimal (int)
    Description:  Converts a binary number into corresponding integer
    Errors:       if not a valid binary number: 
                      print 'Error(bin_to_dec): invalid input' and return empty string
    ---------------------------------------------------
    """
    decimal = 0
    
    if (is_binary(b) == False):
        print('Error(bin_to_dec): invalid input')
        decimal = ""
        
    else:
        i = len(b)-1
        for bit in b:
            if bit == "1":
                decimal += pow(2,i)
            i-=1;
    return decimal

'______________________________________________________________________________'

def dec_to_bin(decimal,size=None):
    """
    ----------------------------------------------------
    Parameters:   decimal (int): input decimal number
                  size (int): number of bits in output binary number
                      default size = None
    Return:       binary (str): output binary number
    Description:  Converts any integer to binary
                  Result is to be represented in size bits
                  pre-pad with 0's to fit the output in the given size
                  If no size is given, no padding is done 
    Asserts:      decimal is an integer
    Errors:       if an invalid size:
                      print 'Error(dec_to_bin): invalid size' and return ''
                  if size is too small to fit output binary number:
                      print 'Error(dec_to_bin): integer overflow' and return ''
    ---------------------------------------------------
    """
    assert type(decimal) is int
    
    binary = ""
    power = 0;
    if decimal == 0:
        binary = "0"
    else:
        while(int(decimal) > 0):
            if decimal%2 != 0: binary = "1" + binary
            else: binary = "0" + binary
            power+=1;
            decimal = int(decimal/2)
       
    if size != None: 
        if (type(size) != int or size < 1):
            print('Error(dec_to_bin): invalid size')
            binary = ""
        else:
            while(len(binary) < size):
                binary = "0" + binary
                
            if len(binary) > size:
                print('Error(dec_to_bin): integer overflow')
                binary = ''
    return binary
            
'______________________________________________________________________________'

def xor(a,b):
    """
    ----------------------------------------------------
    Parameters:   a (str): binary number
                  b (str): binary number
    Return:       decimal (int)
    Description:  Apply xor operation on a and b
    Errors:       if a or b is not a valid binary number 
                      print 'Error(xor): invalid input' and return ''
                  if a and b have different lengths:
                       print 'Error(xor): size mismatch' and return ''
    ---------------------------------------------------
    """
    decimal = ""
    if (is_binary(a) == False or is_binary(b) == False):
        print('Error(xor): invalid input')
    elif (len(a) != len(b)):
        print('Error(xor): size mismatch')
    else:
        for i in range(len(a)):
            if ((a[i] == "1" and b[i] == "0") or (a[i] == "0" and b[i] == "1")):
                decimal += "1"
            else: decimal += "0"
    
    return decimal

'______________________________________________________________________________'

def encode(c,code_type):
    """
    ----------------------------------------------------
    Parameters:   c (str): a character
                  code_type (str): ASCII or B6
    Return:       b (str): corresponding binary number
    Description:  Encodes a given character using the given encoding scheme
                  Current implementation supports only ASCII and B6 encoding
    Errors:       If c is not a single character:
                    print 'Error(encode): invalid input' and return ''
                  If unsupported encoding type:
                    print 'Error(encode): Unsupported Coding Type' and return ''
    ---------------------------------------------------
    """
    b = ""
    if type(c) != str or len(c) != 1:
        print('Error(encode): invalid input')
    else:
        if (code_type == "ASCII"):
            b = str(dec_to_bin(ord(c),8))
        elif (code_type == "B6"):
            for i in range(len(B6)):
                if (c == B6[i]):
                    b = str(dec_to_bin(i, 6))
                    break;
        else: 
            print('Error(encode): Unsupported coding type')
            b = ""

    return b

'______________________________________________________________________________'

def decode(b,code_type):
    """
    ----------------------------------------------------
    Parameters:   b (str): a binary number
                  code_type (str): ASCII or B6
    Return:       c (str): corresponding character
    Description:  Encodes a given character using the given encoding scheme
                  Current implementation supports only ASCII and B6 encoding
    Errors:       If b is not a binary number:
                    print 'Error(decode): invalid input' and return ''
                  If unsupported encoding type:
                    print 'Error(decode): unsupported Coding Type' and return ''
    ---------------------------------------------------
    """
    c = ""
    
    if is_binary(b) == False:
        print('Error(decode): invalid input')
    else:
        key = bin_to_dec(b)
        if (code_type == "ASCII"):
            c = (chr(key))
        elif (code_type == "B6"):
            if (key >= 0 and key < 64) and len(b) < 7:
                c = B6[key]
            else:print('Error(decode_B6): invalid input')
        else: 
            print('Error(decode): unsupported coding type')
            

    return c