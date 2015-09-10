
// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

angular.module('fuzzlabsFilters', []).filter('engine_active', function() {
  return function(input) {
    return input ? '\u2713' : '';
  };
}).filter('capitalize', function() {
  return function(input) {
    return input.charAt(0).toUpperCase() + input.slice(1);
  };
});

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

var fuzzlabsApp = angular.module('fuzzlabsApp', [
        'ui.router',
        'ui.bootstrap',
        'fuzzlabsFilters'
    ]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.config(['$stateProvider',
  function($stateProvider) {

    /*
     * Function to handle navigation bar for page change events.
     */

    var change_page = function(page_name) {
        var items = document.getElementsByClassName("main-menu-item");
        for (var i = 0; i < items.length; i++) {
            $(items[i]).removeClass('active');
        }
        $("li#main_" + page_name).addClass('active');
    }

    $stateProvider.state("Status", {
        views:{
            "status": {
                templateUrl: "templates/status.html"
            }
        },
        abstract: true
    });

    $stateProvider.state("Status.engineError", {
        views:{
            "status": {
                templateUrl: "templates/status_engine_error.html"
            }
        }
    });

    $stateProvider.state("Status.engineOk", {
        views:{
            "status": {
                templateUrl: "templates/status_engine_ok.html"
            }
        }
    });

    $stateProvider.state("Modal", {
        views:{
            "modal": {
                templateUrl: "templates/modal.html"
            }
        },
        abstract: true
    });

    $stateProvider.state("Modal.addNewEngine", {
        url: "/engines/add",
        views:{
            "modal": {
                templateUrl: "templates/add_engine.html"
            }
        },
        onEnter: function() {
            change_page('engines');
        }
    });

    $stateProvider.state("Modal.pageJobs", {
        url: "/jobs",
        views:{
            "modal": {
                templateUrl: "templates/page_jobs.html"
            }
        },
        onEnter: function() {
            change_page('jobs');
        }
    });

    $stateProvider.state("Modal.pageArchives", {
        url: "/archives",
        views:{
            "modal": {
                templateUrl: "templates/page_archives.html"
            }
        },
        onEnter: function() {
            change_page('archives');
        }
    });

    $stateProvider.state("Modal.pageEngines", {
        url: "/engines",
        views:{
            "modal": {
                templateUrl: "templates/page_engines.html"
            }
        },
        onEnter: function() {
            change_page('engines');
        }
    });

    $stateProvider.state("Modal.pageIssues", {
        url: "/issues",
        views:{
            "modal": {
                templateUrl: "templates/page_issues.html"
            }
        },
        onEnter: function() {
            change_page('issues');
        }
    });

    $stateProvider.state("Modal.pageDocumentation", {
        url: "/documentation",
        views:{
            "modal": {
                templateUrl: "templates/documentation/page_main.html"
            }
        },
        onEnter: function() {
            change_page('documentation');
        }
    });

    $stateProvider.state("Modal.pageParser", {
        url: "/parser",
        views:{
            "modal": {
                templateUrl: "templates/page_parser.html"
            }
        },
        onEnter: function() {
            change_page('parser');
        }
    });

}]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.factory('EnginesService', function($interval, $http) {

    var factory = {};

    factory.updateEngineList = function(e_list) {
        window.localStorage.setItem('engines', JSON.stringify(e_list));
    }

    factory.getEngineList = function() {
        var data = JSON.parse(window.localStorage.getItem("engines"));
        if (data != 'undefined' && data != null) return(data);
        return [];
    }

    factory.getCurrentEngine = function() {
        return JSON.parse(window.localStorage.getItem("current_engine"));
    }

    factory.setCurrentEngine = function(engine) {
        window.localStorage.setItem('current_engine', JSON.stringify(engine));
    }

    factory.deleteEngine = function(e_name) {
        var engines = factory.getEngineList();
        var current = factory.getCurrentEngine();
        var was_active = false;
        var was_current = false;

        for (var i = 0; i < engines.length; i++) {
            if (e_name == engines[i].name) {
                if (engines[i] == current) was_current = true;
                was_active = engines[i].active;
                engines.splice(engines.indexOf(engines[i]), 1);
            }
        }

        if (was_current) {
            window.localStorage.setItem('current_engine', '');
        }

        if (was_active && engines.length > 0) {
            engines[0].active = true;
            factory.setCurrentEngine(engines[0]);
        }

        factory.updateEngineList(engines);
    }

    factory.setActiveEngine = function(e_name) {
        var engines = factory.getEngineList();
        var active = null;

        for (var i = 0; i < engines.length; i++) {
            engines[i].active = false;
        }

        for (var i = 0; i < engines.length; i++) {
            if (e_name == engines[i].name) {
                engines[i].active = true;
                active = engines[i];
            }
        }

        if (active != null) {
            window.localStorage.setItem('current_engine', JSON.stringify(active));
            factory.updateEngineList(engines);
        }
    }

    factory.validate_engine_name = function(value) {
        return /[a-zA-Z0-9\-\_\.]{1,128}/.test(value);
    }

    factory.validate_engine_address = function(value) {
        return /[a-zA-Z0-9\-\_\.]{5,256}/.test(value);
    }

    factory.validate_engine_port = function(value) {
        if (isNaN(value) == true) return(false);
        i_val = parseInt(value);
        if (i_val < 1 || i_val > 65535) return(false);
        return(true);
    }

    factory.addEngine = function(name, address, port, password) {
        var engines = factory.getEngineList();
        var registered = false;

        for (var i = 0; i < engines.length; i++) {
            if (engines[i].name == name) registered = true;
            if (engines[i].address == address && engines[i].port == parseInt(port)) registered = true;
        }
        if (registered) {
            alert("This engine is already registered.");
            return(false);
        }

        for (var i = 0; i < engines.length; i++) {
            engines[i].active = false;
        }

        engine = {"active": true, "name": name, "address": address, "port": port, "password": password};
        engines.push(engine)
        factory.updateEngineList(engines);
        factory.setActiveEngine(name);
        return(true);
    }

    return(factory);
});

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.factory('JobsService', ['$interval', '$http', function($interval, $http) {

    var factory = {};

    var jobs = [];

    factory.get_current_engine_cons = function() {
        var c_engine = JSON.parse(window.localStorage.getItem("current_engine"));
        if (c_engine == null) return(null);
        return({"address": c_engine.address + ":" + c_engine.port,
                "password": c_engine.password});
    }

    factory.fetch_jobs = function() {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine == null) {
            jobs = null;
            return(null);
        }
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/status', {'secret': c_engine.password}).
            then(function(response) {
                jobs = response.data;
            }, function(response) {
                jobs = null;
            });
        } else {
            $http.get('http://' + c_engine.address + '/status').
            then(function(response) {
                jobs = response.data;
            }, function(response) {
                jobs = null;
            });
        }
    }

    factory.delete_job = function(job_id) {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/jobs/delete/' + job_id, {'secret': c_engine.password})
        } else {
            $http.get('http://' + c_engine.address + '/jobs/delete/' + job_id);
        }
    }

    factory.pause_job = function(job_id) {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/jobs/pause/' + job_id, {'secret': c_engine.password})
        } else {
            $http.get('http://' + c_engine.address + '/jobs/pause/' + job_id);
        }
    }

    factory.start_job = function(job_id) {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/jobs/resume/' + job_id, {'secret': c_engine.password})
        } else {
            $http.get('http://' + c_engine.address + '/jobs/resume/' + job_id);
        }
    }

    factory.get_jobs = function() {
        return(jobs);
    }

    $interval(function() {
        factory.fetch_jobs();
    }, 7000);

    return(factory);
}]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.factory('ArchivesService', ['$interval', '$http', function($interval, $http) {

    var factory = {};
    var archives = [];

    factory.get_current_engine_cons = function() {
        var c_engine = JSON.parse(window.localStorage.getItem("current_engine"));
        if (c_engine == null) return(null);
        return({"address": c_engine.address + ":" + c_engine.port,
                "password": c_engine.password});
    }

    factory.fetch_archives = function() {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine == null) {
            archives = null;
            return(null);
        }
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/archives', {'secret': c_engine.password}).
            then(function(response) {
                archives = response.data;
            }, function(response) {
                archives = null;
            });
        } else {
            $http.get('http://' + c_engine.address + '/archives').
            then(function(response) {
                archives = response.data;
            }, function(response) {
                archives = null;
            });
        }
    }

    factory.delete_job = function(job_id) {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/archives/delete/' + job_id, {'secret': c_engine.password})
        } else {
            $http.get('http://' + c_engine.address + '/archives/delete/' + job_id);
        }
    }

    factory.restart_job = function(job_id) {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/archives/restart/' + job_id, {'secret': c_engine.password})
        } else {
            $http.get('http://' + c_engine.address + '/archives/restart/' + job_id);
        }
    }

    factory.start_job = function(job_id) {
        var c_engine = factory.get_current_engine_cons();
        if (c_engine.password.length > 0) {
            $http.post('http://' + c_engine.address + '/archives/start/' + job_id, {'secret': c_engine.password})
        } else {
            $http.get('http://' + c_engine.address + '/archives/start/' + job_id);
        }
    }

    factory.get_archives = function() {
        return(archives);
    }

    $interval(function() {
        factory.fetch_archives();
    }, 7000);

    return(factory);
}]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.controller('appInitCtrl', ['$scope', '$state', 'EnginesService', function ($scope, $state, EnginesService) {

    $(document).on("click", "button#status_error_reconnect", function() {
        $state.go("Modal.pageJobs");
    });

    $(document).on("click", "#save_engine", function() {
        var e_name = document.getElementById('new_engine_name').value;
        var e_address = document.getElementById('new_engine_address').value;
        var e_port = document.getElementById('new_engine_port').value;
        var e_password = document.getElementById('new_engine_password').value;
        if (EnginesService.validate_engine_name(e_name) == true &&
            EnginesService.validate_engine_address(e_address) == true &&
            EnginesService.validate_engine_port(e_port) == true) {
            if (EnginesService.addEngine(e_name, e_address, e_port, e_password)) {
                $state.go("Modal.pageEngines");
            }
        }
    });

    /*
     * We force the user to add at least one engine. Without an
     * engine this app is basically useless.
     */

    $(document).on("click", "#cancel_save_engine", function() {
        if (EnginesService.getEngineList().length == 0) { 
            $state.go("Modal.addNewEngine"); 
        } else {
            $state.go("Modal.pageEngines");
        }
    });

    if(!window.localStorage) alert('This application requires HTML5 webstorage support.');

    if (EnginesService.getEngineList().length == 0) {    
        $state.go("Modal.addNewEngine");
    } else {
        $state.go("Modal.pageJobs");
    }

}]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.controller('enginesCtrl', ['$state', '$scope', '$interval', 'EnginesService', function ($state, $scope, $interval, EnginesService) {

    $(document).on("click", "button#add_new_engine", function() {
        $state.go("Modal.addNewEngine");
    });

    $(document).on("click", "button#delete_engine", function() {
        var e_name = $(this).attr('engine');
        EnginesService.deleteEngine(e_name);

        if (EnginesService.getEngineList().length == 0) {
            $state.go("Modal.addNewEngine");
        }

    });

    $(document).on("click", "button#set_active_engine", function() {
        var e_name = $(this).attr('engine');
        EnginesService.setActiveEngine(e_name);
    });

    $interval(function() { 
        $scope.engines = EnginesService.getEngineList();
    }, 1000);

}]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.controller('jobsCtrl', ['$state', '$scope', '$interval', 'JobsService', function ($state, $scope, $interval, JobsService) {

    var on_error_page = false;

    $(document).on("click", "button#archived_jobs", function() {
        $state.go("Modal.pageArchives");
    });

    $(document).on("click", "button#delete_job", function() {
        var job_id = $(this).attr('job_id');
        JobsService.delete_job(job_id);
    });

    $(document).on("click", "button#pause_job", function() {
        var job_id = $(this).attr('job_id');
        JobsService.pause_job(job_id);
    });

    $(document).on("click", "button#start_job", function() {
        var job_id = $(this).attr('job_id');
        JobsService.start_job(job_id);
    });

    $interval(function() {
        var jobs_list = JobsService.get_jobs();
        if (jobs_list == null && on_error_page == false) {
            $state.go("Status.engineError"); 
            on_error_page = true;
            // We give 3 minutes to the user to correct the
            // engine settings. After, if the settings are
            // not corrected we drop to the error page again.
            $interval(function() { 
                on_error_page = false;
            }, 180000, 1);
        }
        $scope.jobs = jobs_list;
    }, 1000);

}]);

// -----------------------------------------------------------------------------
//
// -----------------------------------------------------------------------------

fuzzlabsApp.controller('archivesCtrl', ['$state', '$scope', '$interval', 'ArchivesService', function ($state, $scope, $interval, ArchivesService) {

    var on_error_page = false;

    $(document).on("click", "button#delete_archived", function() {
        var job_id = $(this).attr('job_id');
        ArchivesService.delete_job(job_id);
    });

    $(document).on("click", "button#restart_archived", function() {
        var job_id = $(this).attr('job_id');
        ArchivesService.restart_job(job_id);
    });

    $(document).on("click", "button#start_archived", function() {
        var job_id = $(this).attr('job_id');
        ArchivesService.start_job(job_id);
    });

    $interval(function() {
        var archives_list = ArchivesService.get_archives();
        if (archives_list == null && on_error_page == false) {
            $state.go("Status.engineError");
            on_error_page = true;
            // We give 3 minutes to the user to correct the
            // engine settings. After, if the settings are
            // not corrected we drop to the error page again.
            $interval(function() {
                on_error_page = false;
            }, 180000, 1);
        }
        $scope.archives = archives_list;
    }, 1000);

}]);
