`use strict`;

/*
# Author : Murphy, atorralba
# LICENSE: GPL v3
*/

function exploit() {
  Java.perform( () => {
    const FLAG_GRANT_READ_URI_PERMISSION = 1;
    const FLAG_GRANT_WRITE_URI_PERMISSION = 2;
    const TAINTED_FLAGS = FLAG_GRANT_READ_URI_PERMISSION | FLAG_GRANT_WRITE_URI_PERMISSION;
    const VULNERABLE_URI = 'nnedX://pwned.txt';
  
    const Activity = Java.use('android.app.Activity');
  
    // Intercept setResult
    Activity.setResult.overload('int', 'android.content.Intent').implementation = function (resultCode, data) {
      if (data.getDataString() === VULNERABLE_URI && data.getFlags() === TAINTED_FLAGS) {
        send({ 
          type: 'vuln-event', 
          packageName: this.getPackageName(),
          className: this.getLocalClassName(),
          msg: `${this.getLocalClassName()}: setResult called with ${data.getDataString()} and flags: ${data.getFlags()}` })
      }
      this.setResult(resultCode, data);
    }
    
    const Intent = Java.use('android.content.Intent');
    const Uri = Java.use('android.net.Uri');
    const Context = Java.use('android.content.Context');
    
    const PackageManager = Java.use("android.content.pm.PackageManager");
    const GET_ACTIVITIES = PackageManager.GET_ACTIVITIES.value;
    const ActivityThread = Java.use("android.app.ActivityThread");
    const currentApplication = ActivityThread.currentApplication();
    const context = currentApplication.getApplicationContext();
  
    const ACTIVITY_SERVICE = Context.ACTIVITY_SERVICE.value;
    const ActivityManager = Java.use('android.app.ActivityManager');
    const context1 = ActivityThread.currentApplication();
    const activityManager = Java.cast(context1.getSystemService(ACTIVITY_SERVICE), ActivityManager);
    const tasks = activityManager.getAppTasks();
    if (tasks.isEmpty())
      return null;
  
    const AppTask = Java.use('android.app.ActivityManager$AppTask');
    const task = Java.cast(tasks.get(0), AppTask);
    const exportedActivites = [];
  
    // Obtain Exported Activities
    context.getPackageManager().getPackageInfo(context.getPackageName(), GET_ACTIVITIES)
    .activities.value
    .filter(activityInfo => activityInfo.exported.value === true)
        .forEach(activityInfo => {
          send({ 
            type: 'log-event',
            msg: `Exported activity detected : ${activityInfo.name.value}` 
          });
          exportedActivites.push(activityInfo.name.value);
        });
  
    exportedActivites.forEach( (activityName) => {
      var intent = Intent.$new();
      intent.setClassName(context.getPackageName(), activityName);
      intent.addFlags(TAINTED_FLAGS);
      intent.setData(Uri.parse(VULNERABLE_URI));
      send({ 
        type: 'log-event', 
        msg: `sending startActivityForResult to ${activityName}` 
      });
      task.startActivity(context, intent, null);
      Thread.sleep(1);
    });
  });
}

rpc.exports = {
  exploit
}