import pyvex
import archinfo
import pprint

class Parser:
	DebugLevel = 0
	def __init__(self, bytes, address = 0x0, arch_str = 'x64'):
		if arch_str == 'x64':
			arch = archinfo.ArchAMD64()
		else:
			pass #TODO:

		self.Address = address
		self.irsb = pyvex.IRSB(bytes, address, arch)
		
	def SetDebugLevel(self, level = 0):
		self.DebugLevel = level

	def GetStatements(self):
		return self.irsb.statements
		
	def Trace(self, vars, traces, prefix = '', verbose = 0):
		if verbose>1:
			print(prefix+'Trace:', vars)
		i = len(self.irsb.statements)-1
		
		while i >= 0:
			st = self.irsb.statements[i]
			if not isinstance(st, pyvex.IRStmt.NoOp):
				vars = self.Match(st, vars, traces, prefix = prefix, verbose = verbose)
				
				if len(vars) == 0:
					break
			i -= 1
			
		return vars

	def IsSame(self, data1, data2):
		if isinstance(data1, pyvex.expr.Get):
			pass
		elif isinstance(data1, pyvex.expr.Binop):
			pass
		elif isinstance(data1, pyvex.expr.RdTmp):
			if isinstance(data2, pyvex.expr.RdTmp):
				return data1.tmp == data2.tmp
			elif data1.tmp == data2:
				return True
			
		elif isinstance(data1, pyvex.expr.Load):
			pass
		elif isinstance(data1, pyvex.expr.Unop):
			pass
		elif isinstance(data1, pyvex.expr.Const):
			pass
		elif isinstance(data1, pyvex.expr.CCall):
			pass
		else:
			pass
		return False
		
	def Match(self, st, vars, traces, prefix = '', verbose = 0):
		new_vars = []
		for var in vars:
			matched_vars = []
			matched = False
			if isinstance(st, pyvex.IRStmt.Put):
				reg_name = self.GetRegName(st.offset, st)

				if var['Type'] == 'Register' and var['Value'] == reg_name:
					if verbose>0:
						print prefix+'> Match: ', var, st.data
					matched_vars.append({'Type': 'Tmp', 'Value': st.data})
					traces.append(st)

			elif isinstance(st, pyvex.IRStmt.PutI):
				pass

			elif isinstance(st, pyvex.IRStmt.WrTmp):
				if var['Type'] == 'Tmp' and self.IsSame(var['Value'], st.tmp):
					if isinstance(st.data, pyvex.expr.Get):
						# >> Stmt: t1 = GET:I64(rax)
						reg_name = self.GetRegName(st.data.offset, st)
						
						if verbose>0:
							print prefix+'> Match: ', var, reg_name, st.data.offset
						matched_vars.append({'Type': 'Register', 'Value': reg_name})

					elif isinstance(st.data, pyvex.expr.Binop):
						if verbose>1:
							print prefix+'\tst.data.op: ', st.data.op
							print prefix+'\tst.data.args: ', st.data.args

						for arg in st.data.args:
							if isinstance(arg, pyvex.expr.RdTmp):
								if verbose>0:
									print prefix+'> Match: ', var, arg
								matched_vars.append({'Type': 'Tmp', 'Value': arg})
						matched = True

					elif isinstance(st.data, pyvex.expr.RdTmp):
						if verbose>0:
							print prefix+'> Match: ', var, st.data

						matched_vars.append({'Type': 'Tmp', 'Value': st.data})

					elif isinstance(st.data, pyvex.expr.Load):
						# >> Stmt: t0 = LDle:I64(t1)
						if verbose>0:
							print prefix+'> Match: ', var, st.data.addr
						matched_vars.append({'Type': 'Tmp', 'Value': st.data.addr})
						
					elif isinstance(st.data, pyvex.expr.Unop):
						matched = True
					elif isinstance(st.data, pyvex.expr.Const):
						matched = True
					else:
						matched = True
						
					traces.append(st)

			elif isinstance(st, pyvex.IRStmt.Store):
				stmt_str = st.__str__()
			elif isinstance(st, pyvex.IRStmt.StoreG):
				pass
			elif isinstance(st, pyvex.IRStmt.LoadG):
				pass
			elif isinstance(st, pyvex.IRStmt.CAS):
				pass
			elif isinstance(st, pyvex.IRStmt.LLSC):
				pass
			elif isinstance(st, pyvex.IRStmt.MBE):
				pass
			elif isinstance(st, pyvex.IRStmt.Dirty):
				pass
			elif isinstance(st, pyvex.IRStmt.Exit):
				pass
			else:
				pass

			if matched or len(matched_vars)>0:
				new_vars += matched_vars
				
				if verbose>0:
					print prefix+'\t%x' % self.Address
					self.PrintStatement(st, prefix+'\t')
			else:
				new_vars.append(var)

				if verbose>1:
					print prefix+'\t%x' % self.Address
					self.PrintStatement(st, prefix+'\t')

		if verbose>0 and new_vars != vars:
			print prefix+'\tNew Variables:', new_vars

		return new_vars

	def DumpStData(self, st_data, st, prefix = ''):
		data = {}
		if isinstance(st_data, pyvex.expr.Get):
			data['Type'] = 'Get'
			data['Value'] = self.GetRegName(st_data.offset, st)

		elif isinstance(st_data, pyvex.expr.Binop):
			data['Type'] = 'Binop'
			data['Value'] = {}
			data['Value']['Op'] = st_data.op
			data['Value']['Args'] = []
			for arg in st_data.args:
				data['Value']['Args'].append(self.DumpStData(arg, st))

		elif isinstance(st_data, pyvex.expr.RdTmp):
			data['Type'] = 'Tmp'
			data['Value'] = st_data.tmp
		elif isinstance(st_data, pyvex.expr.Load):
			data['Type'] = 'Load'
			data['ValueType'] = st_data.ty
			data['End'] = st_data.end
			data['Value'] = st_data.addr.tmp
		elif isinstance(st_data, pyvex.expr.Unop):
			data['Type'] = 'Unop'
			#TODO:
		elif isinstance(st_data, pyvex.expr.Const):
			data['Type'] = 'Const'
			data['Value'] = st_data.con.value
		elif isinstance(st_data, pyvex.expr.CCall):
			data['Type'] = 'CCall'
			#TODO:
		else:
			data['Type'] = 'Unknown'
			
		return data

	def Dump(self, st, prefix = ''):
		statement = {}
		if isinstance(st, pyvex.IRStmt.Put):
			statement['Target'] = {'Type': 'Register', 'Value': self.GetRegName(st.offset, st)}
			statement['Data'] = self.DumpStData(st.data, st)
		elif isinstance(st, pyvex.IRStmt.PutI):
			pass
		elif isinstance(st, pyvex.IRStmt.WrTmp):
			statement['Target'] = {'Type': 'Tmp', 'Value': st.tmp}
			statement['Data'] = self.DumpStData(st.data, st)	
		elif isinstance(st, pyvex.IRStmt.Store):
			pass
		elif isinstance(st, pyvex.IRStmt.StoreG):
			pass
		elif isinstance(st, pyvex.IRStmt.LoadG):
			pass
		elif isinstance(st, pyvex.IRStmt.IMark):
			stmt_str = 'IMark'
		elif isinstance(st, pyvex.IRStmt.AbiHint):
			pass
		elif isinstance(st, pyvex.IRStmt.CAS):
			pass
		elif isinstance(st, pyvex.IRStmt.LLSC):
			pass
		elif isinstance(st, pyvex.IRStmt.MBE):
			pass
		elif isinstance(st, pyvex.IRStmt.Dirty):
			pass
		elif isinstance(st, pyvex.IRStmt.Exit):
			pass
		else:
			pass
			
		statement['Address'] = self.Address
		return statement

	def Print(self, forward = True, prefix = ''):
		print prefix+'> %x' % self.Address
		if forward:
			for st in self.irsb.statements:
				if isinstance(st, pyvex.IRStmt.NoOp):
					continue

				self.PrintStatement(st, prefix = prefix)
		else:
			i = len(self.irsb.statements)-1
			
			while i >= 0:
				st = self.irsb.statements[i]
				if not isinstance(st, pyvex.IRStmt.NoOp):
					self.PrintStatement(st, prefix = prefix)
				i -= 1

	def PrintStatement(self, st, prefix = ''):
		stmt_str = ''
		if isinstance(st, pyvex.IRStmt.Put):
			stmt_str = st.__str__(reg_name = self.GetRegName(st.offset, st))
		elif isinstance(st, pyvex.IRStmt.PutI):
			pass
		elif isinstance(st, pyvex.IRStmt.WrTmp):
			if isinstance(st.data, pyvex.expr.Get):
				stmt_str = st.__str__(reg_name = self.GetRegName(st.data.offset, st))
			elif isinstance(st.data, pyvex.expr.Binop):
				stmt_str = st.__str__()
				if self.DebugLevel>0:
					print prefix+'st.data.op: ', st.data.op
					print prefix+'st.data.args: ', st.data.args
			elif isinstance(st.data, pyvex.expr.RdTmp):
				stmt_str = st.__str__()
			elif isinstance(st.data, pyvex.expr.Load):
				stmt_str = st.__str__()
			elif isinstance(st.data, pyvex.expr.Unop):
				stmt_str = st.__str__()
			elif isinstance(st.data, pyvex.expr.Const):
				stmt_str = st.__str__()
			else:
				stmt_str = st.__str__()+' - WrTmp data type:'+str(type(st.data))
				
			if self.DebugLevel>0:
				print prefix+'\tst.tmp: ', st.tmp
		elif isinstance(st, pyvex.IRStmt.Store):
			stmt_str = st.__str__()
		elif isinstance(st, pyvex.IRStmt.StoreG):
			pass
		elif isinstance(st, pyvex.IRStmt.LoadG):
			pass
		elif isinstance(st, pyvex.IRStmt.IMark):
			stmt_str = 'IMark'
		elif isinstance(st, pyvex.IRStmt.AbiHint):
			pass
		elif isinstance(st, pyvex.IRStmt.CAS):
			pass
		elif isinstance(st, pyvex.IRStmt.LLSC):
			pass
		elif isinstance(st, pyvex.IRStmt.MBE):
			pass
		elif isinstance(st, pyvex.IRStmt.Dirty):
			pass
		elif isinstance(st, pyvex.IRStmt.Exit):
			pass
		else:
			stmt_str = st.__str__()

		if stmt_str:
			print prefix+">> Stmt: %s" % (stmt_str)
			print prefix+'\t', type(st)
		else:
			print prefix+'>> Stmt:', 
			st.pp()

	def GetDumpList(self):
		self.TmpRegisters = {}
		read_list_map = {}
		write_list_map = {}
		for st in self.irsb.statements:
			if isinstance(st, pyvex.IRStmt.NoOp):
				continue
				
			if self.DebugLevel>0:
				print ' = '*80
				self.PrintStatement(st)
			(read_list, write_list) = self.DumpStatement(st)

			for dump_info in read_list:
				if read_list_map.has_key(dump_info['Value']):
					continue
				read_list_map[dump_info['Value']] = dump_info

				if self.DebugLevel>0:				
					print '\t\t\t>> Read:', dump_info['Type'], dump_info['Value']

			for dump_info in write_list:
				if write_list_map.has_key(dump_info['Value']):
					continue
				write_list_map[dump_info['Value']] = dump_info
				
				if self.DebugLevel>0:
					print '\t\t\t>> Write:', dump_info['Type'], dump_info['Value']

			if self.DebugLevel>0:
				print ''

		read_list = []
		read_list_str = ''
		for (value, dump_info) in read_list_map.items():
			if dump_info['Type'] == "Const" or dump_info['Type'] == 'Int' or (dump_info['Type'] == "Register" and value.startswith("cc_")) or (dump_info['Type'] == "Register" and value.endswith("ip")):
				continue

			if read_list_str != '':
				read_list_str += ', '
			read_list.append((value, dump_info))

		write_list = []
		write_list_str = ''
		for (value, dump_info) in write_list_map.items():
			if dump_info['Type'] == "Const" or dump_info['Type'] == 'Int' or (dump_info['Type'] == "Register" and value.startswith("cc_")) or (dump_info['Type'] == "Register" and value.endswith("ip")):
				continue
			write_list.append((value, dump_info))

		return (read_list, write_list)

	def GetCommands(self, element_list):
		commands = []
		for (value, dump_info) in element_list:
			if dump_info['Type'] == 'Register':
				commands.append('r %s' % dump_info['Value'])
			elif dump_info['Type'] == 'Memory':
				cmd = 'db'
				if dump_info.has_key('ValueType'):
					if dump_info['ValueType'] == 'Ity_I64':
						cmd = 'dq'
					elif dump_info['ValueType'] == 'Ity_I32':
						cmd = 'dd'
					elif dump_info['ValueType'] == 'Ity_I16':
						cmd = 'dw'
					else:
						cmd = 'db'
						
				commands.append('%s %s L1' % (cmd, dump_info['Value']))
		return commands
		
	def GetWinDBGDumpCommands(self):
		(read_list, write_list) = self.GetDumpList()

		read_commands = self.GetCommands(read_list)
		write_commands = self.GetCommands(write_list)
		
		return (read_commands, write_commands)
		
	def GetRegName(self, reg_offset, st):
		if self.DebugLevel>1:
			print '* GetRegName: %d' % reg_offset
			print 'self.irsb.tyenv:', self.irsb.tyenv
			print 'st.data.result_size(self.irsb.tyenv):', st.data.result_size(self.irsb.tyenv)
		reg_name = self.irsb.arch.translate_register_name(reg_offset, st.data.result_size(self.irsb.tyenv))

		if self.DebugLevel>1:
			print 'reg_name:', reg_name
		return reg_name

	def DumpStatement(self, st):
		read_list = []
		write_list = []
		if isinstance(st, pyvex.IRStmt.NoOp):
			return dump_list

		if self.DebugLevel>0:
			print '* DumpStatement:'
		if isinstance(st, pyvex.IRStmt.Put):
			reg_name = self.GetRegName(st.offset, st)
			if reg_name != 'pc' and reg_name != 'rip' and reg_name != 'eip':
				read_list = self.ConvertTmpToExpr(st.data)
				
				if self.DebugLevel>0:
					print '\t\t>> IRStmt.Put: %s <- %s' % (reg_name, read_list)
				
				if not reg_name.startswith('cc_'):
					write_list.append({'Type': 'Register', 'Value': reg_name, 'StType': 'Put', 'ValueType':'' })
			self.TmpRegisters[st.data] = st
		elif isinstance(st, pyvex.IRStmt.PutI):
			pass
		elif isinstance(st, pyvex.IRStmt.WrTmp):
			if isinstance(st.data, pyvex.expr.Get):
				reg_name = self.GetRegName(st.data.offset, st)
			elif isinstance(st.data, pyvex.expr.Binop):
				if self.DebugLevel>0:
					print 'st.data.op:', st.data.op
					print 'st.data.args:', st.data.args
			elif isinstance(st.data, pyvex.expr.RdTmp):
				pass
			elif isinstance(st.data, pyvex.expr.Load):
				pass
			self.TmpRegisters[st.tmp] = st
		elif isinstance(st, pyvex.IRStmt.Store):
			write_list = self.ConvertTmpToExpr(st.addr, data_type = 'Memory')
			read_list = self.ConvertTmpToExpr(st.data)
			if self.DebugLevel>0:
				print '\t\t>> IRStmt.Store: %s <- %s' % (write_list, read_list)
		elif isinstance(st, pyvex.IRStmt.StoreG):
			pass
		elif isinstance(st, pyvex.IRStmt.LoadG):
			pass
		elif isinstance(st, pyvex.IRStmt.IMark):
			stmt_str = 'IMark'
		elif isinstance(st, pyvex.IRStmt.AbiHint):
			pass
		elif isinstance(st, pyvex.IRStmt.CAS):
			pass
		elif isinstance(st, pyvex.IRStmt.LLSC):
			pass
		elif isinstance(st, pyvex.IRStmt.MBE):
			pass
		elif isinstance(st, pyvex.IRStmt.Dirty):
			pass
		elif isinstance(st, pyvex.IRStmt.Exit):
			pass

		if self.DebugLevel>0:
			print ''
			
		return (read_list, write_list)

	def ConvertTmpToExpr(self, data, level = 1, data_type = ''):
		prefix = '\t'*level
		
		if self.DebugLevel>0:
			print prefix+'-'*80
			print prefix+'* ConvertTmpToExpr:'
			print prefix+'type(data): '+str(type(data))
			print prefix+'data_type: '+data_type
		
		if isinstance(data, pyvex.expr.RdTmp):
			reg = data.tmp
		elif isinstance(data, pyvex.expr.Load):
			if self.DebugLevel>0:
				print prefix+'addr: 0x%x' % data.addr.tmp
				print prefix+'ty: %s' % data.ty
				print prefix+'end: %s' % data.end
			reg = data.addr.tmp
		elif isinstance(data, pyvex.expr.Const):
			if self.DebugLevel>0:
				print prefix+'0x%x' % data.con.value
			return [{'Type': 'Const', 'Value': '0x%x' % data.con.value, 'StType': '', 'ValueType': data.con.type}, ]
		elif isinstance(data, int):
			if self.DebugLevel>0:
				print prefix+'0x%x' % data
			return [{'Type': 'Int', 'Value': '0x%x' % data, 'StType': '', 'ValueType': ''}, ]
		else:
			reg = data

		if not self.TmpRegisters.has_key(reg):
			return []

		if self.DebugLevel>0:
			print prefix+'self.TmpRegisters[%d]: %s' % (reg, self.TmpRegisters[reg])		
		
		st = self.TmpRegisters[reg]

		if isinstance(st, pyvex.IRStmt.NoOp):
			return []

		dump_list = []
		if self.DebugLevel>0:
			print prefix+'type(st): '+str(type(st))
		
		if isinstance(st, pyvex.IRStmt.Put):
			pass
		elif isinstance(st, pyvex.IRStmt.PutI):
			pass
		elif isinstance(st, pyvex.IRStmt.WrTmp):
			if self.DebugLevel>0:
				print prefix+'type(st.data): '+str(type(st.data))
				print prefix+'st.tmp: ', st.tmp
			if isinstance(st.data, pyvex.expr.Get):
				reg_name = self.irsb.arch.translate_register_name(st.data.offset, st.data.result_size(self.irsb.tyenv))
				if self.DebugLevel>0:
					print prefix+'st.data.offset: ', st.data.offset
					print prefix+'reg_name: ', reg_name

				if data_type != 'Memory':
					dump_list.append({'Type': 'Register', 'Value': reg_name, 'StType': 'Get', 'ValueType':'' })
				else:
					dump_list.append({'Type': 'Memory', 'Value': reg_name, 'StType': 'Get', 'ValueType':'' })

				if reg_name.startswith('cc_'):
					dump_list += self.ConvertTmpToExpr(st.data.offset, level+1, data_type = data_type)
			elif isinstance(st.data, pyvex.expr.Binop):
				if self.DebugLevel>0:
					print prefix+'st.data.op: ', st.data.op
					print prefix+'st.data.args: ', st.data.args
				
				arg 1= self.ConvertTmpToExpr(st.data.args[0], level+1, data_type = data_type)[0]
				arg 2= self.ConvertTmpToExpr(st.data.args[1], level+1, data_type = data_type)[0]

				if data_type != 'Memory':
					dump_list.append(arg1)
					dump_list.append(arg2)
					variable_type = 'Value'
				else:
					if arg1['StType'] == 'Binop':
						arg1_value = "("+arg1['Value']+")"
					else:
						arg1_value = arg1['Value']

					if arg2['StType'] == 'Binop':
						arg2_value = "("+arg2['Value']+")"
					else:
						arg2_value = arg2['Value']

					variable_type = 'Memory'
					if st.data.op.startswith('Iop_Add'):
						dump_list.append({'Type': variable_type, 'Value': '%s+%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_Sub'):
						dump_list.append({'Type': variable_type, 'Value': '%s-%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_Xor'):
						dump_list.append({'Type': variable_type, 'Value': '%s^%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_And'):
						dump_list.append({'Type': variable_type, 'Value': '%s&%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_Or'):
						dump_list.append({'Type': variable_type, 'Value': '%s|%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_Shl'):
						dump_list.append({'Type': variable_type, 'Value': '%s<<%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_Shr'):
						dump_list.append({'Type': variable_type, 'Value': '%s<<%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
					elif st.data.op.startswith('Iop_64HLto128'):
						pass

			elif isinstance(st.data, pyvex.expr.RdTmp):
				value_type = st.data.result_type(self.irsb.tyenv)
				for dump_info in self.ConvertTmpToExpr(st.data, level+1, data_type = data_type):
					dump_info['ValueType'] = value_type
					dump_list.append(dump_info)
				
			elif isinstance(st.data, pyvex.expr.Load):
				for dump_info in self.ConvertTmpToExpr(st.data, level+1, data_type = 'Memory'):
					dump_info['ValueType'] = st.data.ty
					dump_list.append(dump_info)
			elif isinstance(st.data, pyvex.expr.Unop):
				dump_list += self.ConvertTmpToExpr(st.data.args[0], level+1, data_type = data_type)
			elif isinstance(st.data, pyvex.expr.Const):
				dump_list += self.ConvertTmpToExpr(st.data, level+1, data_type = data_type)
			elif isinstance(st.data, pyvex.expr.CCall):
				if self.DebugLevel>0:
					print '* st.data.retty: ', st.data.retty
					print '* st.data.cee: ', st.data.cee
					print '* st.data.args: ', st.data.args
				for arg in st.data.args:
					dump_list += self.ConvertTmpToExpr(arg, level+1, data_type = data_type)
				
		elif isinstance(st, pyvex.IRStmt.Store):
			dump_list += self.ConvertTmpToExpr(st.data.tmp, level+1, data_type = data_type)
		elif isinstance(st, pyvex.IRStmt.StoreG):
			pass
		elif isinstance(st, pyvex.IRStmt.LoadG):
			pass
		elif isinstance(st, pyvex.IRStmt.IMark):
			pass
		elif isinstance(st, pyvex.IRStmt.AbiHint):
			pass
		elif isinstance(st, pyvex.IRStmt.CAS):
			pass
		elif isinstance(st, pyvex.IRStmt.LLSC):
			pass
		elif isinstance(st, pyvex.IRStmt.MBE):
			pass
		elif isinstance(st, pyvex.IRStmt.Dirty):
			pass
		elif isinstance(st, pyvex.IRStmt.Exit):
			pass

		if self.DebugLevel>0:
			print prefix+'dump_list: ', dump_list
			print prefix+'-'*80
			print prefix+''
		
		return dump_list
		
	def FindRegister(self, register):
		self.TmpRegisters = {}
		read_list_map = {}
		write_list_map = {}
		for st in self.irsb.statements:
			if isinstance(st, pyvex.IRStmt.NoOp):
				continue
				
			if isinstance(st, pyvex.IRStmt.Put):
				pass
			elif isinstance(st, pyvex.IRStmt.PutI):
				pass
			elif isinstance(st, pyvex.IRStmt.WrTmp):
				if self.DebugLevel>0:
					print prefix+'type(st.data): '+str(type(st.data))
					print prefix+'st.tmp: ', st.tmp
				if isinstance(st.data, pyvex.expr.Get):
					reg_name = self.irsb.arch.translate_register_name(st.data.offset, st.data.result_size(self.irsb.tyenv))
					if self.DebugLevel>0:
						print prefix+'st.data.offset: ', st.data.offset
						print prefix+'reg_name: ', reg_name

					if data_type != 'Memory':
						dump_list.append({'Type': 'Register', 'Value': reg_name, 'StType': 'Get', 'ValueType':'' })
					else:
						dump_list.append({'Type': 'Memory', 'Value': reg_name, 'StType': 'Get', 'ValueType':'' })

					if reg_name.startswith('cc_'):
						dump_list += self.ConvertTmpToExpr(st.data.offset, level+1, data_type = data_type)
				elif isinstance(st.data, pyvex.expr.Binop):
					if self.DebugLevel>0:
						print prefix+'st.data.op: ', st.data.op
						print prefix+'st.data.args: ', st.data.args
					
					arg 1= self.ConvertTmpToExpr(st.data.args[0], level+1, data_type = data_type)[0]
					arg 2= self.ConvertTmpToExpr(st.data.args[1], level+1, data_type = data_type)[0]

					if data_type != 'Memory':
						dump_list.append(arg1)
						dump_list.append(arg2)
						variable_type = 'Value'
					else:
						if arg1['StType'] == 'Binop':
							arg1_value = "("+arg1['Value']+")"
						else:
							arg1_value = arg1['Value']

						if arg2['StType'] == 'Binop':
							arg2_value = "("+arg2['Value']+")"
						else:
							arg2_value = arg2['Value']

						variable_type = 'Memory'
						if st.data.op.startswith('Iop_Add'):
							dump_list.append({'Type': variable_type, 'Value': '%s+%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_Sub'):
							dump_list.append({'Type': variable_type, 'Value': '%s-%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_Xor'):
							dump_list.append({'Type': variable_type, 'Value': '%s^%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_And'):
							dump_list.append({'Type': variable_type, 'Value': '%s&%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_Or'):
							dump_list.append({'Type': variable_type, 'Value': '%s|%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_Shl'):
							dump_list.append({'Type': variable_type, 'Value': '%s<<%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_Shr'):
							dump_list.append({'Type': variable_type, 'Value': '%s<<%s' % (arg1_value, arg2_value), 'StType': 'Binop', 'ValueType':'' })
						elif st.data.op.startswith('Iop_64HLto128'):
							pass

				elif isinstance(st.data, pyvex.expr.RdTmp):
					value_type = st.data.result_type(self.irsb.tyenv)
					for dump_info in self.ConvertTmpToExpr(st.data, level+1, data_type = data_type):
						dump_info['ValueType'] = value_type
						dump_list.append(dump_info)
					
				elif isinstance(st.data, pyvex.expr.Load):
					for dump_info in self.ConvertTmpToExpr(st.data, level+1, data_type = 'Memory'):
						dump_info['ValueType'] = st.data.ty
						dump_list.append(dump_info)
				elif isinstance(st.data, pyvex.expr.Unop):
					dump_list += self.ConvertTmpToExpr(st.data.args[0], level+1, data_type = data_type)
				elif isinstance(st.data, pyvex.expr.Const):
					dump_list += self.ConvertTmpToExpr(st.data, level+1, data_type = data_type)
				elif isinstance(st.data, pyvex.expr.CCall):
					if self.DebugLevel>0:
						print '* st.data.retty: ', st.data.retty
						print '* st.data.cee: ', st.data.cee
						print '* st.data.args: ', st.data.args
					for arg in st.data.args:
						dump_list += self.ConvertTmpToExpr(arg, level+1, data_type = data_type)
					
			elif isinstance(st, pyvex.IRStmt.Store):
				dump_list += self.ConvertTmpToExpr(st.data.tmp, level+1, data_type = data_type)
			elif isinstance(st, pyvex.IRStmt.StoreG):
				pass
			elif isinstance(st, pyvex.IRStmt.LoadG):
				pass
			elif isinstance(st, pyvex.IRStmt.IMark):
				pass
			elif isinstance(st, pyvex.IRStmt.AbiHint):
				pass
			elif isinstance(st, pyvex.IRStmt.CAS):
				pass
			elif isinstance(st, pyvex.IRStmt.LLSC):
				pass
			elif isinstance(st, pyvex.IRStmt.MBE):
				pass
			elif isinstance(st, pyvex.IRStmt.Dirty):
				pass
			elif isinstance(st, pyvex.IRStmt.Exit):
				pass


class Tracker:
	def __init__(self, parser_list):
		self.ParserList = parser_list
		
	def Print(self, forward = True, prefix = ''):
		for parser in self.ParserList:
			parser.Print(False, prefix = '\t\t')
			
	def Trace(self, register, verbose = 0):
		vars = [{'Type': 'Register', 'Value': register}]

		dumps = []
		for parser in self.ParserList:
			traces = []		
			vars = parser.Trace(vars, traces, verbose = 0)
			
			if len(vars) == 0:
				break
				
			for trace in traces:
				dumps.append(parser.Dump(trace))

		return dumps

	def Save(self, filename):
		#filename
		pass

if __name__ == '__main__':
	import sys
	
	bytes_str = sys.argv[0]
	bytes = ''
	for i in range(0, len(bytes_str), 2):
		bytes += chr(int(bytes_str[i:i+2]))
	address = int(sys.argv[2], 16)
	
	parser = Parser(bytes, address, 'x64')
	print parser.GetDumpList()
