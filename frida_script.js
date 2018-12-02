function monitorFunction(package_name, class_name, func_name) {
    try {
        const full_class_name = package_name + '.' + class_name;
        const cls = Java.use(full_class_name);
        var overloads = cls[func_name].overloads;
        for (var index in overloads) {
            var method_overload = overloads[index];
            if (method_overload.hasOwnProperty('argumentTypes')) {
                var msg = "Hooking class: " + class_name + " Function: " + func_name;
                var args_types = [];
                var param_index = 0;
                for (j in method_overload.argumentTypes) {
                    args_types.push(method_overload.argumentTypes[j].className);
                }
                send(msg + '(' + args_types.toString() + ')\n');
                try {
                    method_overload.implementation = function () {
                        var args = [].slice.call(arguments);
                        var result = this[func_name].apply(this, args);
                        var msg = func_name + '(' + args.join(', ') + ') => ' + result + '\n';
                        send(msg);
                        return result;
                    }
                }
                catch(e) { 
                    send("ERROR: " + e); 
                }
            }
        }
    }   
    catch(e) {
        send("Failed hooking class: " + class_name + " Function: " + func_name + "\n" + ' -> ' + e);
    }
}

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
        monitorClass('com.company.activities', 'MainActivity');
    });
}