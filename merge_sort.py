import pandas as pd
import numpy as np

import matplotlib.pyplot as plt

df = pd.read_csv("/home/terrence/Downloads/merge_sort.csv")
print(df.dtypes)

#612281
#0 = n
#1 = T(n)
#2 = T(n)/n^2sqrt(n)
#3 = T(n)/nlog(n)
#4 = T(n)/sqrt(n)log(n)

print(df.columns)

print("========================================================================")
df = df.n.str.split(pat=',',expand=True)

print(df.head(4))
print("======================================================================")
print(df.dtypes)

df = df.rename(columns={0: "n", 1: "T(n)", 2: "T(n)/n^2sqrt(n)",
       3:"T(n)/nlog(n)",4:"T(n)/sqrt(n)log(n)"}, errors="raise")
print(df.dtypes)

df['n'] = df['n'].astype(float, errors = 'raise')
print(df.dtypes)
df.plot.line()
plt.show()
'''






