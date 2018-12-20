/**
    This function is used to create a hook on the method described in: 
    package_name.class_name.func_name(func_args)

    The hook will not modify the functionality of the method but only 
    print out the provided parameters and the result returned every time
    the method is called.

    Arguments:
    package_name - The package name of the class the method is in
    class_name - The class name of the class the method is in
    func_name - The name of the method we want to monitor
    func_args - A list of arguments of the specific method, or undefined
                in case we want to hook all available overrides of the method
*/
function monitorFunction(package_name, class_name, func_name, func_args) {
    try {
        const cls = Java.use(package_name + '.' + class_name);
        var should_hook = true;
        for (var index in cls[func_name].overloads) {
            var method_overload = cls[func_name].overloads[index];
            if (method_overload.hasOwnProperty('argumentTypes')) {
                var msg = "Hooking class: " + class_name + " Function: " + func_name;
                var args_types = [];
                var param_index = 0;
                for (j in method_overload.argumentTypes) { 
                    args_types.push(method_overload.argumentTypes[j].className); 
                }
                // Check if we are looking for a specific overload
                if(func_args != undefined) {
                    should_hook = false;
                    if(method_overload.argumentTypes.length == func_args.length) {
                        var num_of_same_args = 0;
                        for (var a in method_overload.argumentTypes) {
                            if(method_overload.argumentTypes[a] == func_args[a]) 
                                num_of_same_args++;
                            else break;
                        }
                        if(num_of_same_args = func_args.length) should_hook = true;
                    }
                }
                if(should_hook) {
                    send(msg + '(' + args_types.toString() + ')\n');
                    try {
                        method_overload.implementation = function () {
                            var args = [].slice.call(arguments);
                            var result = this[func_name].apply(this, args);
                            var rstr = result.toString();
                            send(func_name+'('+args.join(', ')+') => Result: '+rstr+'\n');
                            return result;
                        }
                    } 
                    catch(e) { send("ERROR: " + e); }
                }
            }
        }
    }   
    catch(e) { 
        send(e); 
    }
}

/**
    This function is used to create a hook on all the methods described in
    the following class: 
    package_name.class_name

    The hook will not modify the functionality of the methods but only 
    print out the provided parameters and the result returned every time
    a method is called.

    Arguments:
    package_name - The package name of the class the method is in
    class_name - The class name of the class the method is in
*/
function monitorClass(package_name, class_name) {
    var full_class_name = package_name + '.' + class_name;
    const cls = Java.use(full_class_name);
    const funcs = Object.getOwnPropertyNames(cls.$classWrapper.prototype);
    for (var f in funcs) {
        try {
            var func_name = funcs[f];
            send("Hooking class: " + class_name + " Function: " + func_name + "\n");
            monitorFunction(package_name, class_name, func_name);
        }   
        catch(e) {
            send("Failed hooking class: " + class_name + " Function: " + func_name + "\n");
        }
    }
}

if (Java.available) {
    Java.perform(function() {
        monitorFunction('org.json', 'JSONObject', 'toString');
        // monitorClass('<package-name>', '<class-name>');
        // monitorClass('org.json', 'JSONObject');
    });
}