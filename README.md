# CCES
Chaotic Cryptography Encryption Shellcode, 100%BypassAV
# HomomorphicsEncryption Class
This class handles decryption of images using homomorphic encryption techniques:
![d302edebef7c8a2bfb35b5fb2d4226c](https://github.com/zzhzhengzh/CCES/assets/114986738/6739d78d-d36d-41ce-a7b3-0d365ad48b00)
# Lorenz and Rossler Map Functions
These functions generate chaotic sequences using Lorenz and Rossler chaotic maps:
![8a01485d42cf8656fedfb48a9c82d02](https://github.com/zzhzhengzh/CCES/assets/114986738/b1d2af5f-71d7-4bf7-8a2f-d8965c05b04a)

# Chaotic Sequence Generation
Generates a chaotic sequence based on initial seeds and parameters:
![633bcc1e16735208d62d70839825554](https://github.com/zzhzhengzh/CCES/assets/114986738/752cd75e-4775-4e9b-ba73-4231a4e35ebd)

# Key Derivation and RSA Functions
Derives a key using PBKDF2 and handles RSA encryption/decryption:
#Encryption and Decryption Functions
Handles the main encryption and decryption logic, combining AES and chaotic sequences:
# Image Parameter Extraction
Extracts parameters from an image 
# File Saving Functions
Saves parameters and encrypted/decrypted text to files

![ad90eeacd74ef0c51e79adbe273920d](https://github.com/zzhzhengzh/CCES/assets/114986738/90fb5128-29b9-4efa-9328-4ca48fdb0e1b)

# Usage
Open the pe file
Enter the parameters **its a really complicate work for pc，will take times to finish encrypt

  ![Screenshot 2024-05-31 114811](https://github.com/zzhzhengzh/CCES/assets/114986738/161f2a8f-1d4f-4180-85ed-6ab3e361ef38)

  Press Encrypt and choose the file you want to encrypt(Any File is acceptable)
  
![Screenshot 2024-05-31 115210](https://github.com/zzhzhengzh/CCES/assets/114986738/fa76bc17-c4d6-47dd-b377-e3e4d176e215)

  After you choose the file it will require you to choose a picture, which enable the program to get parameter by FFT and inverse FFT transformations from the picture.
  
  ![Screenshot 2024-05-31 115248](https://github.com/zzhzhengzh/CCES/assets/114986738/31e19b24-200b-4ec0-b7e1-9fa457dc5fc5)

  Then after some time it will create a folder named with encrypt finished timestamp, involves crypto.dat(The crypted file) and parameter it all used.
  
![Screenshot 2024-05-31 115457](https://github.com/zzhzhengzh/CCES/assets/114986738/b949e925-ec20-4c83-af1c-7fba0e221ed1)

  For decode, it requires you to choose the folder involves crypto.dat and parameters.json.

  ![Screenshot 2024-05-31 115558](https://github.com/zzhzhengzh/CCES/assets/114986738/ef547fd0-e594-451e-ba12-0dd2502510bd)

  After decode it will create a foler with decode file(named with timestamp instead of the original filename)
  
  ![Screenshot 2024-05-31 115633](https://github.com/zzhzhengzh/CCES/assets/114986738/2873ec80-f491-4cd4-9947-d5c02939e350)
  
![Screenshot 2024-05-31 115803](https://github.com/zzhzhengzh/CCES/assets/114986738/bea686dd-ce7f-449f-a8a9-2058ba34d5ba)

And you can compare the hash to confirm the files are the same. The Hash comparer is written with Go and if you want that i will upload it then.
#Payload Bypass
  
  ![35f3b0bf1d01e4e345d3890242fcbe8](https://github.com/zzhzhengzh/CCES/assets/114986738/ab659601-7f8b-4939-ba12-e084793f19b4)

# TODO:
1.enable specific picture to decode.
2.Combine Shellcode Loader and Generate automatically
3.Enable CobaltStrike && Sliver payload generate
      
    
