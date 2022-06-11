# Audit-Active-Directory

For the scripts to work correctly, enable auditing on the domain controller.
Scripts are named by the code of the event on which they are triggered.
Create a new task in the Windows Event Scheduler, you need to specify the trigger on the event, select the security log and specify the event code.
The trigger is ready. Add your script to the action, if the system does not allow scripts, add the appropriate permissive directive to the launch argument.
