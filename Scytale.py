"""
-----------------------------
Name: Torin-Borton-McCallum
Description: Scytale Cipher
-----------------------------
"""
import random
import utilities

class Scytale:
    """
    ----------------------------------------------------
    Cipher name: Spartan Scytale Cipher (500 B.C.)
    Key:         (int): number of rows (diameter of rod)
    Type:        Transposition Cipher
    Description: Assume infinite length rod, i.e., unlimited #columns
                 Construct a table that can fit the plaintext
                 Then read text vertically
                 #rows is equal to the key, final row might be empty
                 User may or may not use padding
    ----------------------------------------------------
    """
    
    DEFAULT_PAD = 'Q'
    DEFAULT_KEY = 4
    
    def __init__(self,key = DEFAULT_KEY, pad = DEFAULT_PAD):
        """
        ----------------------------------------------------
        Parameters:   _key (int): default value: 4
                      _pad (str): padding character, default = 'Q'
        Description:  Scytale constructor
                      sets _key, and _pad
                      if _pad is set to empty string --> no padding
        ---------------------------------------------------
        """
        self._key = self.DEFAULT_KEY
        if key != self.DEFAULT_KEY:
            self.set_key(key)
        self._pad = self.DEFAULT_PAD;
        if key != self.DEFAULT_KEY:
            self.set_pad(pad)
    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (int)
        Description:  Returns a copy of the scytale key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (int): #columns
        Return:       success: True/False
        Description:  Sets Scytale key to given key
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        if Scytale.valid_key(key):
            self._key = key
            return True
        else:
            self._key = self.DEFAULT_KEY 
            return False
    
    def __str__(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       output (str)
        Description:  Constructs and returns a string representation of 
                      Scytale object. Used for testing
                      output format:
                      Scytale Cipher:
                      key = <key>, pad = <pad> OR
                      key = <key>, no padding
        ---------------------------------------------------
        """
        output = "Scytale Cipher:\n"
        output += "key = {}, ".format(self.get_key());
        if (self.get_pad() == ""):
            output += "no padding"
        else: 
            output += "pad = "
            output += self.get_pad()
        return output
        
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Scytale key
                      A valid key is an integer >= 1
        ---------------------------------------------------
        """
        if type(key) is int and key >= 1:
            return True
        else:
            return False
    
    def set_pad(self,pad):
        """
        ----------------------------------------------------
        Parameters:   pad (str): a padding character
        Return:       success: True/False
        Description:  Sets scytale pad to given character
                      a pad should be a single character or an empty string
                      if invalid pad, set to default value
                      empty string means no padding
        ---------------------------------------------------
        """
        if Scytale.valid_pad(pad):
            self._pad = pad
            return True
        else:
            self._pad = self.DEFAULT_PAD 
            return False

    def get_pad(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       pad (str): current padding character
        Description:  Returns a copy of current padding character
        ---------------------------------------------------
        """ 
        return self._pad
    
    @staticmethod
    def valid_pad(pad):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   pad (?):
        Returns:      True/False
        Description:  Checks if given pad is a valid Scytale pad
                      single character or an empty string
        ---------------------------------------------------
        """
        if type(pad) == str and (len(pad) == 0 or len(pad) == 1):
            return True
        else:
            return False
    

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Scytale Cipher
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        assert type(plaintext) is str#assertion
        
        ciphertext = ""
        rows = self.get_key()
        letters = len(plaintext)
        columns = int(letters/rows)
        
        if (letters%rows != 0): columns += 1;#if there is a decimal value increase to next int value
        mylist = utilities.new_matrix(rows, columns, self.get_pad())#create a matrix in the appropriate size and fill with pad character
        mylist = Scytale.fill_list(mylist, columns, plaintext)#use static function to fill list with characters from plaintext
        
        #read matrix in opposite direction to encrypt and add to ciphertext
        for c in range(columns):
            for r in range(rows):
                ciphertext += mylist[r][c]
                
        return ciphertext
        
        
    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Scytale Cipher
                      Removes padding if it exist
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) is str
        
        plaintext = "" #return str
        
        columns = self.get_key()#number of columns is equal to key
        letters = len(ciphertext)#letters = length of text
        rows = int(letters/columns)#rows = letters/columns and increase if there is a remainder
        if (letters%columns != 0): rows += 1;
        padnum = rows*columns - letters#number of pad characters is number of empty spaces in matrix 
        
        #padnum is only used when no padding is in text otherwise matrix is already filled
        
        #fill list with padding (whitespace) in appropriate location
        
        mylist = utilities.new_matrix(rows, columns, self.get_pad())#create an empty list
        for i in range(padnum):
            mylist[rows-1-i][columns-1] = " "#fill far right column from bottom up w number of pad characters
        
        mylist = Scytale.fill_list(mylist, columns, ciphertext)#static function to fill matrix with text char
            
        #go through each column and each row and add the character to plaintext
        for c in range(columns):
            for r in range(rows):
                plaintext += mylist[r][c]
        pad = self.get_pad()
        if pad == "": pad = " "
        return plaintext.rstrip(pad)#strip the right side for pad char and return
    
    @staticmethod
    def fill_list(mylist, columns, text):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   mylist: list that may have white spaces to indicate padding areas
                      columns: number of columns to insert characters into, rows doesn't matter
                      text: text to retrieve char from an insert into mylist
        Returns:      mylist[]
        Description:  fills a matrix full of characters based on a given string
        ---------------------------------------------------
        """
        r = 0;
        c = 0;
        for char in text:
            if mylist[r][c] == " ":#indicates padded area, go to next position in list 
                if c == columns-1:#if last position in column go to next row
                    c = 0;
                    r +=1;
                else: c+= 1; 
            mylist[r][c] = char;
            if c == columns-1:
                c = 0;
                r +=1;
            else: c+= 1;
        return mylist

    @staticmethod
    def cryptanalyze(ciphertext,args = [100,None,0.9]):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
                      args (list):
                        max_key (int): default 100
                        dictionary_file (str): default = None
                        threshold (float): default = 0.9
        Return:       key,plaintext
        Description:  Cryptanalysis of Scytale Cipher
                      Apply brute force from key 1 up to max_key (inclusive)
                      Assumes user passes a valid args list
        ---------------------------------------------------
        """
        #extract arguments
        max_key, dictionary_file, threshold = args        
        dict_list = utilities.load_dictionary(dictionary_file)
        found = False
        i = 0
        
        while i < max_key and found is False: 
            i += 1
            scytale = Scytale(i, None) 
            plaintext = scytale.decrypt(ciphertext)
            found = utilities.is_plaintext(plaintext, dict_list, threshold)
                
        key = i
            
        if i >= max_key:
            print('Scytale.cryptanalysis: cryptanalysis failed')
            return '',''
        return key,plaintext

