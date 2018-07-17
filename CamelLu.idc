//CamelLu.idc  
#include <idc.idc>  
static CamelLu()  
{  
    auto addr,path,file,imagebase;  
    Message("Functions' Names Dumper - CamelLu(2011.7.19)\n");  
    file = fopen(GetInputFilePath(),"rb");  
    if (0 == file)  
    {  
        Warning("open INPUTFILE failed!");  
        return;  
    }  
    if (0 != fseek(file,0x3c,0))  
    {  
        Warning("seek e_lfanew failed!");  
        fclose(file);  
        return;  
    }  
    imagebase = readlong(file,0);  
    if (0 != fseek(file,imagebase + 0x34,0))  
    {  
        Warning("seek imagebase failed!");  
        fclose(file);  
        return;          
    }  
    imagebase = readlong(file,0);  
    fclose(file);  
    path = AskFile(1,"*.lu","Please enter output file name");  
    if (BADADDR == path)  
    {  
        Warning("AskFile failed!");  
        return;  
    }  
    file = fopen(path,"w");  
    if (0 == file)  
    {  
        Warning("fopen failed!");  
        return;  
    }  
    addr = MinEA();  
    if ("" != GetFunctionName(addr))  
        fprintf(file,"%X---%s\n",addr,GetFunctionName(addr));  
    for(addr = NextFunction(addr);BADADDR != addr;addr = NextFunction(addr))      
         fprintf(file,"%X-%s\n",addr - imagebase,GetFunctionName(addr));  
    fclose(file);  
    Message("output functions' names finished!");  
}  