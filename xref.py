from idautils import *
from idc import *
from idaapi import *
import sqlite3
import os

def main(filename):
	ea = 0x13ab54
	
	if os.path.exists(filename):
		try:
			os.remove(name)
			Message("Previous Database %s has been removed\n" % filename)
		except:
			Message("Error! Can not remove file.")
	
	# create databse
	db = sqlite3.connect(filename)
	cur = db.cursor()
	sql_create = """create table if not exists functions(
							id integer primary key,
							address text unique,
							name varchar(255))"""
	cur.execute(sql_create)
	
	sql_insert = "insert into functions (address, name) values (?, ?)"
	
	for xref in XrefsTo(ea,0):
		ref_type = ""
		if xref.type == dr_W:
			ref_type = dr_W
		elif xref.type == dr_R:
			ref_type = dr_R
		else:
			ref_type = "Unknown"
		cur.execute(sql_insert,(xref.frm, GetFunctionName(xref.frm)))
	
	db.commit()
	db.close()
	
if __name__=='__main__':
	f = AskFile(1,"*.sqlite","Select the output file")
	if BADADDR == f:
		Warning('AskFile Failed!')
	else:
		main(f)