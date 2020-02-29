def mainFunc(i,nthreads,domains,worksheet):
    if i==0:
        for j in range(1,20):
            row=j
            worksheet.write(row,col,j)
            worksheet.write(row,col+1,"i is 0")
            worksheet.write(row,col+2,"hello1")
            row = row+1
    elif i==nthreads-1:
        for j in range(40,70):
            row=j
            worksheet.write(row,col,j)
            worksheet.write(row,col+1,"i is 1")
            worksheet.write(row,col+2,"hello2")
            row = row+1
    else:
        for j in range(100,120):
            row=j
            worksheet.write(row,col,j)
            worksheet.write(row,col+1,"i is 2")
            worksheet.write(row,col+2,"hello3")
            row = row+1
               
#resultFile=input("Enter the name of the excel file wherein you want to save the results (example - abc.xlsx) : ")
workbook = xlsxwriter.Workbook("aaa.xlsx")
worksheet = workbook.add_worksheet()
worksheet.write(0,0,"SUBDOMAIN NAME")
worksheet.write(0,1,"CNAME")
worksheet.write(0,2,"HTTP STATUS ( 0 implies unable to connect to page)")

nthreads=4
for i in range(nthreads):
    print("I - ",i)
    t = Thread(target=mainFunc, args=(i,nthreads,domains,worksheet,))
    t.start()
