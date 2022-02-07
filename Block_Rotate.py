"""
-----------------------------
Name: Torin-Borton-McCallum
Description: Block Rotate Cipher
-----------------------------
"""
import random
import utilities

class Block_Rotate:
    """
    ----------------------------------------------------
    Cipher name: Block Rotate Cipher
    Key:         (B,R): block size, number of rotations
    Type:        Transposition Cipher
    Description: Breaks plaintext into blocks of size B
                 Rotates each block by R
                 Uses padding for the final block
    ----------------------------------------------------
    """
    
    DEFAULT_PAD = 'q'
    DEFAULT_KEY = (1,0)
    
    def __init__(self,key=DEFAULT_KEY,pad=DEFAULT_PAD):
        """
        ----------------------------------------------------
        Parameters:   _key (int,int): default value: (1,0)
                      _pad (str): a character, default = q
        Description:  Block Rotate constructor
                      sets _key and _pad
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
        Return:       key (int,int)
        Description:  Returns a copy of the Block Rotate key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (b,r): tuple(int,int)
        Return:       success: True/False
        Description:  Sets block rotate cipher key to given key
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        if Block_Rotate.valid_key(key):
            b = key[0]
            r = key[1]%b
            
            self._key = (b,r)
            
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
                      Block Rotate object. Used for testing
                      output format:
                      Block Rotate Cipher:
                      key = <key>, pad = <pad>
        ---------------------------------------------------
        """
        output = 'Block Rotate Cipher:\n'
        output += "key = {}, pad = {}".format(self.get_key(), self.get_pad())
        return output    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid block rotate key
        ---------------------------------------------------
        """
        if len(key) == 2 and type(key) == tuple and type(key[0]) == int and type(key[1]) == int and key[0] > 0:
            return True
        else:
            return False
    
    def set_pad(self,pad):
        """
        ----------------------------------------------------
        Parameters:   pad (str): a padding character
        Return:       success: True/False
        Description:  Sets block rotate pad to given character
                      a pad should be a single character
                      if invalid pad, set to default value
        ---------------------------------------------------
        """ 
        if Block_Rotate.valid_pad(pad):
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
        Description:  Encryption using Block Rotation Cipher
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """       
        assert type(plaintext) == str
        
        positions = utilities.get_positions(plaintext, "\n")    
        plaintext = utilities.clean_text(plaintext, "\n")
        
        (b,r) = self.get_key()
        pad = self.get_pad()
        mylist = utilities.text_to_blocks(plaintext, b, True, pad)
        ciphertext = ''
        
        for word in mylist:
            ciphertext += utilities.shift_string(word, r, "l")
            
        ciphertext = utilities.insert_positions(ciphertext, positions)    
            
        return ciphertext

    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Block Rotation Cipher
                      Removes padding if it exist
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """    
        assert type(ciphertext) == str
        
        positions = utilities.get_positions(ciphertext, "\n")    
        ciphertext = utilities.clean_text(ciphertext, "\n")
        
        (b,r) = self.get_key()
        pad = self.get_pad()
        mylist = utilities.text_to_blocks(ciphertext, b, True, pad)
        plaintext = ''
        
        for word in mylist:
            plaintext += utilities.shift_string(word, r, "r")
            
        plaintext = utilities.insert_positions(plaintext,positions)     
        return plaintext.rstrip(pad)

    @staticmethod
    def cryptanalyze(ciphertext,args=[0,0,0,None,0.8]):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
                      args (list):
                            b0: minimum block size (int): default = 0
                            bn: maximum block size (int): default = 0
                            r: rotations (int): default = 0
                            dictionary_file (str): default = None
                            threshold (float): default = 0.8
        Return:       key,plaintext
        Description:  Cryptanalysis of Block Rotate Cipher
                      Returns plaintext and key (r,b)
                      Attempts block sizes from b0 to bn (inclusive)
                      If bn is invalid or unspecified use 20
                      Minimum valid value for b0 is 2
                      Assumes user passes a valid args list
        ---------------------------------------------------
        """
        #extract arguments
        b0, bn, r, dictionary_file, threshold = args        
        dict_list = utilities.load_dictionary(dictionary_file)
        
        block = Block_Rotate()
        plaintext = ""
        found = False
        
        if bn < 2:
            bn = 20
            
        if b0 <= 0:
            b0 = 2
        
        for i in range(b0,bn+1):
            
            if r == 0:
                for j in range(i):
                    key = (i,j)
                    block.set_key(key)
                    plaintext = block.decrypt(ciphertext)
                    found = utilities.is_plaintext(plaintext, dict_list, threshold)
                    
                    if found is True: break
            else:
                key = (i,r)
                block.set_key(key)
                plaintext = block.decrypt(ciphertext)
                found = utilities.is_plaintext(plaintext, dict_list, threshold)
                if found is True: break
            if found == True:
                break

            
        if found == False:
            print('Block_Rotate.cryptanalyze: cryptanalysis failed')
            return '',''

        return key,plaintext

