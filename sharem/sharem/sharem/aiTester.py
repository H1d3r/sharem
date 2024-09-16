from openai import OpenAI
from .test1_helper import *


model3="gpt-3.5-turbo"
model4="gpt-4o"
# myPrompt= completePrompt


cT=0

def print_nested_dict(d, useColors, indent=0):
    cList=[mag,cya,blu,gre,yel,red]
    # useColors=False
    if useColors:
        cList=[mag,cya,blu,gre,yel,red]
        color1=gre
        color2=cya
    else:
        cList=["","","","","","","","","","","","","",""]
        color1=""
        color2=""

    global cT
    cT+=1
    out=""

    for key, value in d.items():
        if isinstance(value, dict):
            cT=dict_depth(sample_dict)
            out+=('\n ' * indent + cList[cT]+ f"{key}:"+res+"\n")
            out+=print_nested_dict(value, useColors,indent + 1)+"\n"
        elif isinstance(value, list):
            out+=('  ' * indent  +color1+f"{key}:" + res +" "+"\n")
            for item in value:
                if isinstance(item, dict):
                    out+=print_nested_dict(item, useColors,indent + 1)+"\n"
                else:
                    out+=('  ' * (indent + 1) + str(item)+"\n")
            # out+=('  ' * indent + "]\n")
        else:
            out+=('  ' * indent + color2 + f"{key}:"+res +f" {value}"+"\n")
    return out
   
        
# Example usage

def dict_depth(d):
    if isinstance(d, dict):
        return 1 + max((dict_depth(value) for value in d.values()), default=0)
    return 0

# Example usage
sample_dict = {
    "level1": {
        "level2": {
            "level3": {
                "level4": "value"
            }
        },
        "level2_2": "value"
    },
    "level1_2": {
        "level2_3": "value"
    }
}



def printDict(myDict):
    item=print_nested_dict(myDict,True)

    indent=0
    width=94
    split_lines = item.split('\n')

    for item in split_lines:
        wrapped_item = textwrap.fill(str(item), width=width, initial_indent='  ' * (indent + 1), subsequent_indent='  ' * (indent + 1))
        print(wrapped_item)

def AI_func(OPENAI_API_KEY,model,myPrompt):
  client = OpenAI(api_key=OPENAI_API_KEY)
  yel = '\u001b[33;1m'

  completion = client.chat.completions.create(
    model=model,
    messages=[
      {"role": "user", "content": myPrompt }
    ], 
    temperature=0.7,
  )

  # print(type(completion.choices[0].message))
  # print(completion.choices[0].message)
  # print ("********************")

  t=0
  outB=""
  for each in completion.choices[0].message:
    if t==0:
      # print (each[0])
      out=each[1]

    #   print ("********************")
    # print (each)
    # try:
    #   outB+=each[t]
    # except:
    #   pass
    t+=1
  
  # print (outB)
  # print ("********************")
  return out

# print (AI_func(OPENAI_API_KEY,model4,myPrompt))
