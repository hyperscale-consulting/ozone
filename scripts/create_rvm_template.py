from hyperscale.ozone.rvm import RoleVendingMachine

rvm = RoleVendingMachine()
print(rvm.create_template().to_yaml())
