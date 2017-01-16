import angr
import claripy
target_address = 0x0000000000400AF5 #put addree here 
p = angr.Project('qq', load_options={'auto_load_libs': False}) 
#arg = claripy.BVS('arg', 8 * 32) #from argv
#state = p.factory.blank_state(addr=start_address)
#state = p.factory.entry_state(args=[ "./binary"]) 

pg = p.factory.path_group() 
#pg.explore(avoid = lambda p: "QQ" in p.state.posix.dumps(1))
pg.explore(find=target_address)
print repr(pg.found[0].state.posix.dumps(0))# 0 is input 1 is output
