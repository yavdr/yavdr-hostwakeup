#include <stdio.h>
#include <stdlib.h>
#include <dbus/dbus.h>

int main(int argc, char *argv[])
{
  DBusError err;
  DBusConnection *conn;
  DBusMessage *msg;
  DBusMessageIter args;
  DBusPendingCall *pending;
  char **hosts;
  int num_hosts;
  int ret;
  int i;

  dbus_error_init(&err);
  conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
  if (dbus_error_is_set(&err)) {
     fprintf(stderr, "Connection Error (%s)\n", err.message);
     dbus_error_free(&err);
     }
  if (NULL == conn)
     exit(1); 

  msg = dbus_message_new_method_call("de.yavdr.hostwakeup", "/Hosts", "de.yavdr.hostwakeup", "List");
  if (NULL == msg) {
     fprintf(stderr, "Message Null\n");
     exit(1);
     }

  if (!dbus_connection_send_with_reply(conn, msg, &pending, -1)) {
     fprintf(stderr, "Out Of Memory!\n");
     exit(1);
     }
  if (NULL == pending) {
     fprintf(stderr, "Pending Call Null\n");
     exit(1);
     }
  dbus_connection_flush(conn);
  dbus_message_unref(msg);

  dbus_pending_call_block(pending);
  msg = dbus_pending_call_steal_reply(pending);
  if (NULL == msg) {
     fprintf(stderr, "Reply Null\n");
     exit(1);
     }
  dbus_pending_call_unref(pending);
  if (!dbus_message_iter_init(msg, &args))
     fprintf(stderr, "Message has no arguments!\n");
  else if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &hosts, &num_hosts, DBUS_TYPE_INVALID)) {
     if (hosts != NULL)
        dbus_free_string_array(hosts);
     fprintf(stderr, "Argument is not a string array!\n");
     exit(1);
     }
  if (hosts != NULL) {
     printf("found %d host%s\n", num_hosts, (num_hosts == 1 ? "" : "s"));
     for (i = 0; i < num_hosts; i++)
         printf("host %d: %s\n", i + 1, hosts[i]);
     dbus_free_string_array(hosts);
     }
  dbus_message_unref(msg);
  return 0;
}
