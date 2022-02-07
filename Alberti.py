"""
-----------------------------
Name: Torin-Borton-McCallum
Description: Alberti Cipher
-----------------------------
"""
import random
import utilities

class Alberti:
    """
    ----------------------------------------------------
    Cipher name: Alberti Cipher (1472)
    Key:         (pointer,in_wheel)
    Type:        Substitution Cipher
    Description:Default mode:
                    Outer wheel has a..z0..9
                    Given inner wheel has some random arrangement of a..z0..9
                    Perform simple substitution
                Simple mode:
                    Outer wheel has a..z0..9
                    Inner wheel uses default value
                    Perform simple substitution
                Periodic mode:
                    Outer wheel has a..z0..9
                    Given inner wheel has some random arrangement of a..z0..9
                    Perform simple substitution while changing inner wheel once
                        clockwise every PERIOD number of characters
                In all modes:
                    Outer wheel at a is aligned with (pointer) at inner wheel
                    outer and inner wheel has same characters
                    In encryption/decryption Ignore characters not 
                        defined in the base (wheels)
                     encryption/decryption is case insensitive -->
                        output is always lower case
    ----------------------------------------------------
    """
    #constants
    OUT_WHEEL = 'abcdefghijklmnopqrstuvwxyz0123456789'
    DEFAULT_KEY = ('k','k0v9p1j8m2r7d3l5g4a6zteunwbosfchyqix')
    PERIOD = 8
    MODES = ['default','simple','periodic']
    
    def __init__(self,key=DEFAULT_KEY,mode='default'):
        """
        ----------------------------------------------------
        Parameters:   _key (str,str): pointer,base
                      _mode (str): default = 'default'
        Description:  Alberti Cipher constructor
                      sets _key and _mode
        ---------------------------------------------------
        """
        self._mode = self.MODES[0];
        if mode in self.MODES:
            self.set_mode(mode)
        
        self._key = self.DEFAULT_KEY
        if key != self.DEFAULT_KEY:
            self.set_key(key)
    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (str,str)
        Description:  Returns a copy of the Alberti key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str,str): tuple(str,str)
        Return:       success: True/False
        Description:  Sets Alberti cipher key to given key
                      if invalid key --> set to default key
                      does not update in_wheel in simple mode
        ---------------------------------------------------
        """ 
        
        if Alberti.valid_key(key):
            self._key = key
            if self.get_mode() == self.MODES[1]:
                self._key = (key[0],self.DEFAULT_KEY[1])
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
                      Alberti object. Used for testing
                      output format:
                      Alberti Cipher:
                      key = <key>, mode = <mode>
                      <out_wheel>
                      <in_wheel>
        ---------------------------------------------------
        """
        out_wheel, in_wheel = self.get_wheels()
        output = "Alberti Cipher:\n"
        output += "key = {}, mode = ".format(self.get_key());
        output += self.get_mode()
        output += "\n{}\n{}".format(out_wheel,in_wheel)
        return output
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid alberti key
        ---------------------------------------------------
        """
        if (len(key[0]) == 1 and key[0] in Alberti.OUT_WHEEL and key[1].isalnum() and len(key[1]) == len(Alberti.OUT_WHEEL) and key[0] != "" and key[1] != ""):
            return True
        else:return False
       
    def set_mode(self,mode):
        """
        ----------------------------------------------------
        Parameters:   mode (str): Alberti cipher mode
        Return:       success: True/False
        Description:  Sets Alberti cipher to given mode
                      valid only if defined in MODES
                      Otherwise set to 'default'
                      when setting to simple mode, set in_wheel to default value
        ---------------------------------------------------
        """ 
        if mode in self.MODES and mode != "":
            self._mode = mode
            if (mode == self.MODES[1]):
                self.set_key((self.get_key()[0],self.DEFAULT_KEY[1]))
            return True
        else:
            self._mode = self.MODES[0] 
            return False
    
    def get_mode(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       mode (str): current cipher mode
        Description:  Returns a copy of current mode
        ---------------------------------------------------
        """ 
        return self._mode
    
    def get_wheels(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       out_wheel (str)
                      in_wheel (str)
        Description:  returns out and in wheels aligned at pointer
        ---------------------------------------------------
        """
        out_wheel = self.OUT_WHEEL
        in_wheel = self.get_key()[1]
        n = utilities.get_positions(in_wheel, self.get_key()[0])[0][1]
        in_wheel = utilities.shift_string(in_wheel, n, 'l')
        return out_wheel,in_wheel

            

    @staticmethod
    def random_wheel():
        """
        ----------------------------------------------------
        Static Method
        Parameters:   -
        Returns:      random_wheel (str)
        Description:  Generates a random arrangement of outer wheel
        ---------------------------------------------------
        """
        out_wheel = Alberti().OUT_WHEEL
        return ''.join(random.sample(out_wheel, len(out_wheel)))

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Alberti Cipher
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        assert type(plaintext) == str
        
        out_wheel, in_wheel = self.get_wheels()
        
        ciphertext = ""
        for i in range(len(plaintext)):
            if plaintext[i].lower() not in out_wheel:
                ciphertext += plaintext[i]
            else:
                index = utilities.get_positions(out_wheel, plaintext[i].lower())[0][1]
                ciphertext += in_wheel[index]
            if self.get_mode() == self.MODES[2] and (i+1)%self.PERIOD == 0 and i > 0:
                in_wheel = utilities.shift_string(in_wheel, 1, 'r')
                
        return ciphertext
    
    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Alberti Cipher
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) == str
        out_wheel, in_wheel = self.get_wheels()
        
        plaintext = ""
        for i in range(len(ciphertext)):
            if ciphertext[i].lower() not in in_wheel:
                plaintext += ciphertext[i]
            else:
                index = utilities.get_positions(in_wheel, ciphertext[i].lower())[0][1]
                plaintext += out_wheel[index]
            if self.get_mode() == self.MODES[2] and (i+1)%self.PERIOD == 0 and i >0:
                in_wheel = utilities.shift_string(in_wheel, 1, 'r')
                
        return plaintext
    

    @staticmethod
    def cryptanalyze(ciphertext,args=['','','',None,0.8]):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
                      args (list):
                            pointer: (str): default = ''
                            in_wheel: (str): default = ''
                            mode: (str): default = ''
                            dictionary_file (str): default = None
                            threshold (float): default = 0.8
        Return:       key,plaintext
        Description:  Cryptanalysis of Alberti Cipher
                      Returns plaintext and key (pionter,in_wheel)
                      Assumes user passes a valid args list
        ---------------------------------------------------
        """  
        #extract arguments
        pointer,in_wheel, mode, dictionary_file, threshold = args        
        dict_list = utilities.load_dictionary(dictionary_file)
        
        mode_num = 0
        cycle = False
        found = False
        key = (pointer,in_wheel)
        alberti = Alberti()
        
        if in_wheel == "":
            in_wheel = alberti.DEFAULT_KEY[1]
        
        if mode == "":
            cycle = True
        
        alberti.set_mode(mode)
             
        while found == False and (cycle == True or mode_num == 0):
            if cycle == True:
                alberti.set_mode(alberti.MODES[mode_num])
            
            for char in ciphertext:
                pointer = char;
                key = (pointer,in_wheel);
                alberti.set_key(key);
                plaintext = alberti.decrypt(ciphertext)
                found = utilities.is_plaintext(plaintext, dict_list, threshold)
                if found is True: 
                    break 
            mode_num +=1  
            if mode_num >2: cycle = False
        
        if found == False:
            print('Alberti.cryptanalyze: cryptanalysis failed')
            return '',''
        return (key,plaintext)