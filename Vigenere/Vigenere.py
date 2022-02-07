"""
-----------------------------
Name: Torin Borton-McCallum
Description: Vigenere Cipher
-----------------------------
"""
"""Hope you have a great day my dude"""
import utilities
import Shift_cipher
  
class Vigenere:
    """
    ----------------------------------------------------
    Cipher name: Vigenere Cipher
    Key:         (str): a character or a keyword
    Type:        Polyalphabetic Substitution Cipher
    Description: if key is a single characters, uses autokey method
                    Otherwise, it uses a running key
                 In autokey: key = autokey + plaintext (except last char)
                 In running key: repeat the key
                 Substitutes only alpha characters (both upper and lower)
                 Preserves the case of characters
    ----------------------------------------------------
    """
    
    DEFAULT_KEY = 'k'
    
    def __init__(self,key=DEFAULT_KEY):
        """
        ----------------------------------------------------
        Parameters:   _key (str): default value: 'k'
        Description:  Vigenere constructor
                      sets _key
                      if invalid key, set to default key
        ---------------------------------------------------
        """
        self._key = self.DEFAULT_KEY
        if key != self.DEFAULT_KEY:
            self.set_key(key)
    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (str)
        Description:  Returns a copy of the Vigenere key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str): non-empty string
        Return:       success: True/False
        Description:  Sets Vigenere cipher key to given key
                      All non-alpha characters are removed from the key
                      key is converted to lower case
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        if Vigenere.valid_key(key):
            new_key = ""
            for char in key:
                if char.isalpha():
                    new_key += char.lower()
            self._key = new_key
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
                      Vigenere object. Used for testing
                      output format:
                      Vigenere Cipher:
                      key = <key>
        ---------------------------------------------------
        """
        return "Vigenere Cipher:\nkey = {}".format(self.get_key())
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Vigenere key
                      A valid key is a string composing of at least one alpha char
        ---------------------------------------------------
        """
        valid = False

        if type(key) is str:
            for char in key:
                if char.isalpha():
                    valid = True
                    break
        return valid

    @staticmethod
    def get_square():
        """
        ----------------------------------------------------
        static method
        Parameters:   -
        Return:       vigenere_square (list of string)
        Description:  Constructs and returns vigenere square
                      The square contains a list of strings
                      element 1 = "abcde...xyz"
                      element 2 = "bcde...xyza" (1 shift to left)
        ---------------------------------------------------
        """
        element = 'abcdefghijklmnopqrstuvwxyz'
        vigener_square = [element]
        for _ in range(len(element)-1):
            element = utilities.shift_string(element, 1, 'l')
            vigener_square.append(element)
        return vigener_square

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Vigenere Cipher
                      May use an auto character or a running key
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        assert type(plaintext) == str, 'invalid plaintext'
        
        if len(self._key) == 1:
            return self._encrypt_auto(plaintext)
        else:
            return self._encrypt_run(plaintext)

    def _encrypt_auto(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Private helper function
                      Encryption using Vigenere Cipher Using an autokey
        ---------------------------------------------------
        """
        ciphertext = ''
        stripped_plaintext = ""
        non_alpha = [] #char to add after encryption
        subtext = self.get_key()
        base = self.get_square()
        
        for i in range(len(plaintext)):
            char = plaintext[i]
            if char.isalpha() == False:
                non_alpha.append([char,i])
            else: 
                stripped_plaintext += char
        subtext += stripped_plaintext[:-1]

        for i in range(len(subtext)):
            x = ord(stripped_plaintext[i].lower()) - 97
            y = ord(subtext[i].lower()) - 97
            if (stripped_plaintext[i].isupper()):
                ciphertext += base[x][y].upper()
            else:
                ciphertext += base[x][y]
            
        ciphertext = utilities.insert_positions(ciphertext, non_alpha)
        return ciphertext

    def _encrypt_run(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Private helper function
                      Encryption using Vigenere Cipher Using a running key
        ---------------------------------------------------
        """
        capital = False
        ciphertext = ''
        base = self.get_square()
        key = self.get_key()
        index = 0
        sub = ""
        for char in plaintext:
            if char.isalpha() == False:  
                sub += char
            else:
                sub += key[index]
                index += 1;
                if index >= len(key):
                    index = 0
                    
        for i in range(len(sub)):
            char = plaintext[i]
            if char.isalpha():
                if char.upper() == char:
                    capital = True
                y = ord(plaintext[i].lower()) - 97
                x = ord(sub[i]) - 97
                if capital == True:
                    ciphertext += base[x][y].upper()
                    capital = False
                else:
                    ciphertext += base[x][y]
            else:ciphertext += plaintext[i]
        return ciphertext
    
    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Vigenere Cipher
                      May use an auto character or a running key
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) == str, 'invalid input'
        
        if len(self._key) == 1:
            return self._decryption_auto(ciphertext)
        else:
            return self._decryption_run(ciphertext)

    def _decryption_auto(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Private Helper method
                      Decryption using Vigenere Cipher Using autokey
        ---------------------------------------------------
        """
        non_alpha = []
        plaintext = ""
        subtext = self.get_key()
        if ciphertext[0].isupper(): subtext = subtext.upper()
        difference = 0
        base = self.get_square()
        
        for i in range(len(ciphertext)):
    
            if ciphertext[i].isalpha() == False:
                non_alpha.append([ciphertext[i],i])
                difference += 1
            else:
                x = ord(subtext[i-difference].lower()) - 97
                y = utilities.get_positions(base[x], ciphertext[i].lower())[0][1]
    
                if (ciphertext[i].isupper()):
                    plaintext += base[0][y].upper()
                    subtext += base[0][y].upper()
                else:
                    plaintext += base[0][y]
                    subtext += base[0][y]
            
        plaintext = utilities.insert_positions(plaintext, non_alpha)
        return plaintext

    def _decryption_run(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Private Helper method
                      Decryption using Vigenere Cipher Using running key
        ---------------------------------------------------
        """
        plaintext = ''
        capital = False
        base = self.get_square()
        key = self.get_key()
        index = 0
        sub = ""
        for char in ciphertext:
            if char.isalpha() == False:
                sub += char.lower()
            else:
                sub += key[index]
                index += 1;
                if index >= len(key):
                    index = 0
                    
        for i in range(len(sub)):
            char = ciphertext[i]
            if char.isalpha():
                if char.upper() == char:
                    capital = True
                
                x = ord(sub[i]) - 97
                y = utilities.get_positions(base[x], char.lower())[0][1]
                
                if capital == True:
                    plaintext += base[0][y].upper()
                    capital = False
                else:plaintext += base[0][y]
            else:plaintext += char
        return plaintext
    
    @staticmethod
    def cryptanalyze_key_length(ciphertext):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   ciphertext (str)
        Return:       key_lenghts (list)
        Description:  Finds key length for Vigenere Cipher
                      Combines results of Friedman and Cipher Shifting
                      Produces a list of key lengths from the above two functions
                      Start with Friedman and removes duplicates
        ---------------------------------------------------
        """
        friedman = Cryptanalysis.friedman(ciphertext)
        c_shift = Cryptanalysis.cipher_shifting(ciphertext,)
        key_lengths = []
        for item in friedman:
            if item in c_shift:
                key_lengths.append(item)
                
        for item in friedman:
            if item not in key_lengths:
                key_lengths.append(item)
                
        for item in c_shift:
            if item not in key_lengths:
                key_lengths.append(item)
        
        return key_lengths

    @staticmethod
    def cryptanalyze(ciphertext):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
        Return:       key,plaintext
        Description:  Cryptanalysis of Shift Cipher
                      Returns plaintext and key (shift,start_indx,end_indx)
                      Uses the key lengths produced by Vigenere.cryptanalyze_key_length
                      Finds out the key, then apply chi_squared
                      The key with the lowest chi_squared value is returned
        Asserts:      ciphertext is a non-empty string
        ---------------------------------------------------
        """
        assert type(ciphertext) is str
        #clean ciphertext
        new_ciphertext = utilities.clean_text(ciphertext, utilities.get_base('nonalpha') + "\t \n")
        assert ciphertext != ''
                
        key_length = Vigenere.cryptanalyze_key_length(new_ciphertext)#find key_length values
        min_key = ["",None,""] 
        
        for k in key_length:
            C = utilities.text_to_blocks(new_ciphertext, k, True, )#blocks
            S = utilities.blocks_to_baskets(C)#baskets

            key = ''
            for basket in S:
                value = Shift.cryptanalyze(basket,[utilities.get_base('lower'), -1, k])[0][0]#find shift value from Shift.cryptanalyze() key
                key += (chr(value + 97))#convert value to char (ex. 0 -> 'a')
            vigenere_cipher = Vigenere(key)
            plaintext = vigenere_cipher.decrypt(ciphertext)
            chi = Cryptanalysis.chi_squared(plaintext, )

            if (min_key[1] == None or min_key[1] > chi):
                min_key = [key,chi,plaintext]

        return min_key[0],min_key[2]
    
    
    
    
    
    
    
    