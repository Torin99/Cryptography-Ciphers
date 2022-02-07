"""
-----------------------------
Name: Torin Borton-McCallum
Description: Shift Cipher
-----------------------------
"""
"""Hope you have a great day my dude"""
import utilities
class Cryptanalysis:
    """
    ----------------------------------------------------
    Description: Class That contains cryptanalysis functions
                 Mainly for Vigenere and Shift Cipher 
                     but can be used for other ciphers
    ----------------------------------------------------
    """
    @staticmethod    
    def index_of_coincidence(text,base_type = None):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   text(str)
                      base_type(str): default = None
        Return:       I (float): Index of Coincidence
        Description:  Computes and returns the index of coincidence 
                      Uses English alphabets by default, otherwise, given base_type
        Asserts:      text is a string
        ----------------------------------------------------
        """
        assert type(text) is str
        
        I = 0#return value
        freq = utilities.get_freq(text, base_type)#frequency of every character in text from given base_type        
        N = sum(freq)#total number of characters
        if N == 0: return 0 

        """"
            sigma(i=0,25)[ni(ni-1)]
        I = -----------------------
                    N(N-1)
        """
        for i in freq:
            I += i * (i-1)
        I = I/((N*(N-1)))
        return I       

    @staticmethod
    def IOC(text):
        """
        ----------------------------------------------------
        Same as Cryptanalysis.index_of_coincidence(text)
        ----------------------------------------------------
        """
        return Cryptanalysis.index_of_coincidence(text)
    
    @staticmethod
    def friedman(ciphertext):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext(str)
        Return:       list of two key lengths [int,int]
        Description:  Uses Friedman's test to compute key length
                      returns best two candidates for key length
                        Best candidates are the floor and ceiling of the value
                          Starts with most probable key, for example: 
                          if friedman = 3.2 --> [3, 4]
                          if friedman = 4.8 --> [5,4]
                          if friedman = 6.5 --> [6, 5]
        Asserts:      ciphertext is a non-empty string
        ----------------------------------------------------
        """
        assert type(ciphertext) is str and len(ciphertext) > 0
        #return values  
        x = 0
        y = 0
        """"
                   0.0265n
        k = -----------------------
            (0.065-I) + n(I-0.0385)
        """
        I = Cryptanalysis.index_of_coincidence(ciphertext, None)#IOC
        N = len(ciphertext)
        K = (0.0265*N)/((0.065 - I)+N*(I-0.0385))
        temp = K - int(K)#checks if decimal is > 0.5 for return value positions
        if temp < 0.5:
            x = int(K)#remove decimal
            y = x +1
        else: 
            y = int(K)
            x = y +1
        return [x,y]

    @staticmethod
    def chi_squared(text,language='English'):
        """
        ----------------------------------------------------
        Parameters:   text (str)
                      language (str): default = 'English'
        Return:       result (float)
        Description:  Calculates the Chi-squared statistics 
                      for given text against given language
                      Only alpha characters are considered
        Asserts:      text is a string
        Errors:       if language is unsupported:
                        print error msg: 'Error(chi_squared): unsupported language'
                        return -1
        ----------------------------------------------------
        """
        assert type(text) is str
        lan_freq = utilities.get_language_freq(language)#frequency of characters in english language
        #Error: language is unsupported
        if lan_freq == []:
            print("Error(chi_squared): unsupported language")
            return -1
        result  = 0
        freq = utilities.get_freq(text,None)
        N = sum(freq)#char count
        if N == 0: return -1#empty list return -1
        
        """" Chi Squared Formula
                            (Ci-Ei)^2
        x^2 = sigma(i = a,z) -----------
                               Ei
        """
        #print("length = ",N)
        for i in range(26):
            den = lan_freq[i] * N #numerator/Ei -> expected count of char i
            num = pow(freq[i]-den,2)#denominator/ (ci - Ei)^2 -> ci = count of char i
            result += num/den
        return result

    @staticmethod
    def cipher_shifting(ciphertext,args =[20,26]):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
                      args (lsit):
                          max_key_length (int): default = 20
                          factor (int): default = 26
        Return:       Best two key lengths [int,int]
        Description:  Uses Cipher shifting to compute key length
                      returns best two candidates for key length
                      cipher shift factor determines how many shifts should be made
                      Cleans the text from all non-alpha characters before shifting
                      Upper and lower case characters are considered different chars
                      The returned two keys, are the ones that produced highest matches
                          if equal, start with smaller value
        Asserts:      ciphertext is a non-empty string
        ----------------------------------------------------
        """
        assert type(ciphertext) is str
        max_key_length,factor = args#extraction
        ciphertext = utilities.clean_text(ciphertext, utilities.get_base('nonalpha') + "\t \n")#clean ciphertext
        assert ciphertext != ""
        key_lengths = [[0,0],[0,0]]#2 most matched key lengths: [# of matches, index]
        matches = 0
        shift_cipher = ciphertext
        
        for shift in range(1,factor):
            new_shift = shift#used with modulas when shift value goes over max key
            if shift > max_key_length:
                new_shift = shift % max_key_length
                
            shift_cipher = " " + shift_cipher[:-1]#shift ciphertext by one character
            matches = utilities.compare_texts(shift_cipher, ciphertext)
            
            #store if shifted ciphertext has a high in matches
            if matches > key_lengths[0][0]:
                key_lengths[1] = key_lengths[0]
                key_lengths[0] = [matches,new_shift]
            elif matches > key_lengths[1][0]:
                key_lengths[1] = [matches,new_shift]
        
        return[key_lengths[0][1],key_lengths[1][1]]        

class Shift:
    """
    ----------------------------------------------------
    Cipher name: Shift Cipher
    Key:         (int,int,int): shifts,start_index,end_index
    Type:        Shift Substitution Cipher
    Description: Generalized version of Caesar cipher
                 Uses a subset of BASE for substitution table
                 Shift base by key and then substitutes
                 Case sensitive
                 Preserves the case whenever possible
                 Uses circular left shift
    ----------------------------------------------------
    """
    BASE = utilities.get_base('all') + ' '
    DEFAULT_KEY = (3,26,51)   #lower case Caesar cipher
    
    def __init__(self,key=DEFAULT_KEY):
        """
        ----------------------------------------------------
        Parameters:   _key (int,int,int): 
                        #shifts, start_index, end_indx 
                        (inclusive both ends of indices)
        Description:  Shift constructor
                      sets _key
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
        Description:  Returns a copy of the Shift key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str): non-empty string
        Return:       success: True/False
        Description:  Sets Shift cipher key to given key
                      #shifts is set to smallest value
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        if Shift.valid_key(key):
            (shifts,start,end) = key
            if shifts < 0:#case for negative values, subtract from base_size and reset
                base_size = end - start + 1
                shifts = base_size + shifts
            self._key = (shifts,start,end)
            return True
        else:
            self._key = self.DEFAULT_KEY
            return False

    def get_base(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       base (str)
        Description:  Returns a copy of the base characters
                      base is the subset of characters from BASE
                      starting at start_index and ending with end_index
                      (inclusive both ends)
        ---------------------------------------------------
        """
        key = self.get_key()
        start = key[1]
        end = key[2] + 1
        base = self.BASE[start:end]
        return base
        
    def __str__(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       output (str)
        Description:  Constructs and returns a string representation of 
                      Shift object. Used for testing
                      output format:
                      Shift Cipher:
                      key = <key>
                      base = <base>
                      sub  = <sub>
        ---------------------------------------------------
        """
        base = self.get_base()
        output = 'Shift Cipher:\nkey = {}\nbase = {}\nsub  = {}'.format(self.get_key(),base,self.get_sub(base))
        return output
    
    def get_sub(self, base):
        """helper function: returns substitution string"""
        shift = self.get_key()[0]
        sub = utilities.shift_string(base, shift, 'l')
        return sub
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Shift key
                      A valid key is a tuple consisting of three integers
                          shifts, start_index, end_index
                      The shifts can be any integer
                      The start and end index should be positive values
                      such that start is smaller than end and both are within BASE
        ---------------------------------------------------
        """
        valid = False
        
        if type(key) == tuple and len(key) == 3:#is a tuple consisting of three integers
            (shifts,start_index,end_index) = key
            if type(shifts) is int:#The shifts can be any integer
                if type(start_index) == int and type(end_index) == int:#The start and end index should be positive values
                    if start_index >= 0 and end_index > 0 and start_index < end_index:#such that start is smaller than end
                        if start_index < len(Shift.BASE) and end_index <= len(Shift.BASE):#and both are within BASE
                            valid = True
                        
        return valid

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Shift Cipher
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        assert type(plaintext) is str
        ciphertext = ""
        base = self.get_base()
        sub = self.get_sub(base)
        
        for char in plaintext:
            if char not in base:#add characters that can't be substituted
                ciphertext += char
            else:
                index = utilities.get_positions(base, char)[0][1]#find position of char in base str
                ciphertext += sub[index]#add char from sub string at same position
        return ciphertext

    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Shift Cipher
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) is str
        plaintext = ""
        base = self.get_base()
        sub = self.get_sub(base)
        
        for char in ciphertext:
            if char not in sub:#add characters that can't be substituted
                plaintext += char
            else:
                index = utilities.get_positions(sub, char)[0][1]#find position of char in sub str
                plaintext += base[index]#add char from base string at same position
        return plaintext

    @staticmethod
    def cryptanalyze(ciphertext,args=['',-1,0]):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
                      args (list):
                            base: (str): default = ''
                            shifts: (int): default = -1
                            base_length (int): default = -1 
        Return:       key,plaintext
        Description:  Cryptanalysis of Shift Cipher
                      Returns plaintext and key (shift,start_indx,end_indx)
                      Uses the Chi-square method
                      Assumes user passes a valid args list
        ---------------------------------------------------
        """
        base, shifts, base_length = args#extract arguments
        key = (0,0,0)
        plaintext = ''
        return_value = [None,(0,0,0),'']#chi,key,plaintext
        
        #1- Known base and number of shifts (trivial case)
        if base != '' and shifts != -1 and base_length != -1:
            start_index = utilities.get_positions(Shift.BASE, base[0])[0][1]
            end_index = utilities.get_positions(Shift.BASE, base[-1])[0][1]
            
            key = (shifts, start_index, end_index)
            shift_cipher = Shift(key)
            plaintext = shift_cipher.decrypt(ciphertext)
        #2- Known base but unknown number of shifts
        elif base != '' and shifts == -1:
            start_index = utilities.get_positions(Shift.BASE, base[0])[0][1]
            end_index = utilities.get_positions(Shift.BASE, base[-1])[0][1]
            
            for i in range(len(base)):
                key = (i, start_index, end_index)
                shift_cipher = Shift(key)
                plaintext = shift_cipher.decrypt(ciphertext)
                chi = Cryptanalysis.chi_squared(plaintext, )
                if (return_value[0] == None or return_value[0] >= chi):
                    return_value = [chi,key,plaintext]
            key = return_value[1]
            plaintext = return_value[2]          
        #3- unknown base, known shifts and known base length
        elif base == '' and shifts != -1 and base_length != -1:
            for start_index in range(len(Shift.BASE)):
                if (start_index + base_length < len(Shift.BASE)):
                        end_index = start_index + base_length + 1
                else: break
                for i in range(base_length):
                    end_index = start_index + i + 2
                    key = (shifts, start_index, end_index) 
                    shift_cipher = Shift(key)
                    plaintext = shift_cipher.decrypt(ciphertext)                    
                    chi = Cryptanalysis.chi_squared(plaintext,)
                    if return_value[0] == None or chi <= return_value[0]:
                        return_value = [chi,key,plaintext]
            key = return_value[1]
            plaintext = return_value[2]
        #4- unknown base and shifts, known base length
        elif base == '' and shifts == -1:
            for start_index in range(len(Shift.BASE)):
                if (start_index + base_length < len(Shift.BASE)):
                        end = start_index + base_length + 1
                else: break
                for i in range(base_length):
                    end = i + start_index + 2
                    for shifts in range(base_length):
                        key = (shifts, start_index, end) 
                        shift_cipher = Shift(key)
                        plaintext = shift_cipher.decrypt(ciphertext)
                        chi = Cryptanalysis.chi_squared(plaintext, )                        
                        if return_value[0] == None or return_value[0] >= chi:
                            return_value = [chi,key,plaintext]
                    
            key = return_value[1]
            plaintext = return_value[2]
        return key,plaintext
    
    
    
    
    
    
    
    
    