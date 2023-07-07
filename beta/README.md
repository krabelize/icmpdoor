# encryption using a onetime pad concept
- Ensure the libraries listed in requirements.txt are installed via ```python3 -m pip install -r requirements.txt```
- Create a copy of `icmpdoor.py` called `otp.py`
- Run ```python3 ./icmpdoor.py -g```
- Enter a password
- Take the output and modify lines 24-25 accordingly on ```otp.py```
- Lines 26-28 may be changed as needed on ```otp.py```
- Copy ```otp.py``` to the target machine
- Run ```python3 ./otp.py``` from the target machine
- Run ```python3 ./otp.py -m server``` from the Command and Control host
- When finished run ```___otp___``` in the shell from the Command and Control host

# to-do
- Merge icmpdoor.py with icmpdoorRaw.py to make a unified concept