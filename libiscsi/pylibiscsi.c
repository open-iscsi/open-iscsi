/*
 * iSCSI Administration library
 *
 * Copyright (C) 2008-2009 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2008-2009 Hans de Goede <hdegoede@redhat.com>
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#include <Python.h>
#include "libiscsi.h"

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#define MODINITERROR return NULL
#define PYNUM_FROMLONG PyLong_FromLong
#define PYSTR_FROMSTRING PyUnicode_FromString
#else
#define MODINITERROR return
#define PYNUM_FROMLONG PyInt_FromLong
#define PYSTR_FROMSTRING PyString_FromString
#endif

#define RET_TRUE_ELSE_FALSE { Py_RETURN_TRUE; } else { Py_RETURN_FALSE; }
#define CMP_TO_RICHCMP(cmpfunc) \
	int comp_res = cmpfunc(self, other); \
	switch (op) { \
	    case Py_LT: \
		if (comp_res < 0) RET_TRUE_ELSE_FALSE \
	    case Py_LE: \
		if (comp_res <= 0) RET_TRUE_ELSE_FALSE \
	    case Py_EQ: \
		if (comp_res == 0) RET_TRUE_ELSE_FALSE \
	    case Py_NE: \
		if (comp_res != 0) RET_TRUE_ELSE_FALSE \
	    case Py_GT: \
		if (comp_res > 0) RET_TRUE_ELSE_FALSE \
	    default: \
		if (comp_res >= 0) RET_TRUE_ELSE_FALSE \
	}

static struct libiscsi_context *context = NULL;

/****************************** helpers ***********************************/
static int check_string(const char *string)
{
	if (strlen(string) >= LIBISCSI_VALUE_MAXLEN) {
		PyErr_SetString(PyExc_ValueError, "string too long");
		return -1;
	}
	return 0;
}

/********************** PyIscsiChapAuthInfo ***************************/

typedef struct {
	PyObject_HEAD

	struct libiscsi_auth_info info;
} PyIscsiChapAuthInfo;

static int PyIscsiChapAuthInfo_init(PyObject *self, PyObject *args,
				    PyObject *kwds)
{
	int i;
	PyIscsiChapAuthInfo *chap = (PyIscsiChapAuthInfo *)self;
	char *kwlist[] = {"username", "password", "reverse_username",
				"reverse_password", NULL};
	const char *string[4] = { NULL, NULL, NULL, NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwds,
					"zz|zz:chapAuthInfo.__init__",
					kwlist, &string[0], &string[1],
					&string[2], &string[3]))
		return -1;

	for (i = 0; i < 4; i++)
		if (string[i] && check_string(string[i]))
			return -1;

	memset (&chap->info, 0, sizeof(chap->info));
	chap->info.method = libiscsi_auth_chap;
	if (string[0])
		strcpy(chap->info.chap.username, string[0]);
	if (string[1])
		strcpy(chap->info.chap.password, string[1]);
	if (string[2])
		strcpy(chap->info.chap.reverse_username, string[2]);
	if (string[3])
		strcpy(chap->info.chap.reverse_password, string[3]);

	if (libiscsi_verify_auth_info(context, &chap->info)) {
		PyErr_SetString(PyExc_ValueError,
				libiscsi_get_error_string(context));
		return -1;
	}
	return 0;
}

static PyObject *PyIscsiChapAuthInfo_get(PyObject *self, void *data)
{
	PyIscsiChapAuthInfo *chap = (PyIscsiChapAuthInfo *)self;
	const char *attr = (const char *)data;

	if (!strcmp(attr, "username")) {
		return PYSTR_FROMSTRING(chap->info.chap.username);
	} else if (!strcmp(attr, "password")) {
		return PYSTR_FROMSTRING(chap->info.chap.password);
	} else if (!strcmp(attr, "reverse_username")) {
		return PYSTR_FROMSTRING(chap->info.chap.reverse_username);
	} else if (!strcmp(attr, "reverse_password")) {
		return PYSTR_FROMSTRING(chap->info.chap.reverse_password);
	}
	return NULL;
}

static int PyIscsiChapAuthInfo_set(PyObject *self, PyObject *value, void *data)
{
	PyIscsiChapAuthInfo *chap = (PyIscsiChapAuthInfo *)self;
	const char *attr = (const char *)data;
	const char *str;

	if (!PyArg_Parse(value, "s", &str) || check_string(str))
		return -1;

	if (!strcmp(attr, "username")) {
		strcpy(chap->info.chap.username, str);
	} else if (!strcmp(attr, "password")) {
		strcpy(chap->info.chap.password, str);
	} else if (!strcmp(attr, "reverse_username")) {
		strcpy(chap->info.chap.reverse_username, str);
	} else if (!strcmp(attr, "reverse_password")) {
		strcpy(chap->info.chap.reverse_password, str);
	}

	return 0;
}

static int PyIscsiChapAuthInfo_compare(PyIscsiChapAuthInfo *self,
				       PyIscsiChapAuthInfo *other)
{
	int r;

	r = strcmp(self->info.chap.username, other->info.chap.username);
	if (r)
		return r;

	r = strcmp(self->info.chap.password, other->info.chap.password);
	if (r)
		return r;

	r = strcmp(self->info.chap.reverse_username,
		   other->info.chap.reverse_username);
	if (r)
		return r;

	r = strcmp(self->info.chap.reverse_password,
		   other->info.chap.reverse_password);
	return r;
}

PyObject *PyIscsiChapAuthInfo_richcompare(PyIscsiChapAuthInfo *self,
	                                  PyIscsiChapAuthInfo *other,
					  int op)
{
	CMP_TO_RICHCMP(PyIscsiChapAuthInfo_compare)
}

static PyObject *PyIscsiChapAuthInfo_str(PyObject *self)
{
	PyIscsiChapAuthInfo *chap = (PyIscsiChapAuthInfo *)self;
	char s[1024], reverse[512] = "";

	if (chap->info.chap.reverse_username[0])
		snprintf(reverse, sizeof(reverse), ", %s:%s",
			 chap->info.chap.reverse_username,
			 chap->info.chap.reverse_password);

	snprintf(s, sizeof(s), "%s:%s%s", chap->info.chap.username,
		 chap->info.chap.password, reverse);

	return PYSTR_FROMSTRING(s);
}

static struct PyGetSetDef PyIscsiChapAuthInfo_getseters[] = {
	{"username", (getter)PyIscsiChapAuthInfo_get,
		(setter)PyIscsiChapAuthInfo_set,
		"username", "username"},
	{"password", (getter)PyIscsiChapAuthInfo_get,
		(setter)PyIscsiChapAuthInfo_set,
		"password", "password"},
	{"reverse_username", (getter)PyIscsiChapAuthInfo_get,
		(setter)PyIscsiChapAuthInfo_set,
		"reverse_username", "reverse_username"},
	{"reverse_password", (getter)PyIscsiChapAuthInfo_get,
		(setter)PyIscsiChapAuthInfo_set,
		"reverse_password", "reverse_password"},
	{NULL}
};

PyTypeObject PyIscsiChapAuthInfo_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libiscsi.chapAuthInfo",
	.tp_basicsize = sizeof (PyIscsiChapAuthInfo),
	.tp_getset = PyIscsiChapAuthInfo_getseters,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE
#ifndef IS_PY3K
	// Py_TPFLAGS_CHECKTYPES is only needed on Python 2
	|  Py_TPFLAGS_CHECKTYPES
#endif
	,
	.tp_richcompare = (richcmpfunc)PyIscsiChapAuthInfo_compare,
	.tp_init = PyIscsiChapAuthInfo_init,
	.tp_str = PyIscsiChapAuthInfo_str,
	.tp_new = PyType_GenericNew,
	.tp_doc = "iscsi chap authentication information.",
};

/***************************** PyIscsiNode  ********************************/

typedef struct {
	PyObject_HEAD

	struct libiscsi_node node;
} PyIscsiNode;

static int PyIscsiNode_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	PyIscsiNode *node = (PyIscsiNode *)self;
	char *kwlist[] = {"name", "tpgt", "address", "port", "iface", NULL};
	const char *name = NULL, *address = NULL, *iface = NULL;
	int tpgt = -1, port = 3260;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|isis:node.__init__",
					 kwlist, &name, &tpgt, &address,
					 &port, &iface))
		return -1;
	if (address == NULL) {
		PyErr_SetString(PyExc_ValueError, "address not set");
		return -1;
	}
	if (check_string(name) || check_string(address) || check_string(iface))
		return -1;

	strcpy(node->node.name, name);
	node->node.tpgt = tpgt;
	strcpy(node->node.address, address);
	node->node.port = port;
	strcpy(node->node.iface, iface);

	return 0;
}

static PyObject *PyIscsiNode_get(PyObject *self, void *data)
{
	PyIscsiNode *node = (PyIscsiNode *)self;
	const char *attr = (const char *)data;

	if (!strcmp(attr, "name")) {
		return PYSTR_FROMSTRING(node->node.name);
	} else if (!strcmp(attr, "tpgt")) {
		return PYNUM_FROMLONG(node->node.tpgt);
	} else if (!strcmp(attr, "address")) {
		return PYSTR_FROMSTRING(node->node.address);
	} else if (!strcmp(attr, "port")) {
		return PYNUM_FROMLONG(node->node.port);
	} else if (!strcmp(attr, "iface")) {
		return PYSTR_FROMSTRING(node->node.iface);
	}
	return NULL;
}

static int PyIscsiNode_set(PyObject *self, PyObject *value, void *data)
{
	PyIscsiNode *node = (PyIscsiNode *)self;
	const char *attr = (const char *)data;
	const char *str;
	int i;

	if (!strcmp(attr, "name")) {
		if (!PyArg_Parse(value, "s", &str) || check_string(str))
			return -1;
		strcpy(node->node.name, str);
	} else if (!strcmp(attr, "tpgt")) {
		if (!PyArg_Parse(value, "i", &i))
			return -1;
		node->node.tpgt = i;
	} else if (!strcmp(attr, "address")) {
		if (!PyArg_Parse(value, "s", &str) || check_string(str))
			return -1;
		strcpy(node->node.address, str);
	} else if (!strcmp(attr, "port")) {
		if (!PyArg_Parse(value, "i", &i))
			return -1;
		node->node.port = i;
	} else if (!strcmp(attr, "iface")) {
		if (!PyArg_Parse(value, "s", &str) || check_string(str))
			return -1;
		strcpy(node->node.iface, str);
	}

	return 0;
}

static int PyIscsiNode_compare(PyIscsiNode *self, PyIscsiNode *other)
{
	int res;

	res = strcmp(self->node.name, other->node.name);
	if (res)
		return res;

	if (self->node.tpgt < other->node.tpgt)
		return -1;
	if (self->node.tpgt > other->node.tpgt)
		return -1;

	res = strcmp(self->node.address, other->node.address);
	if (res)
		return res;

	if (self->node.port < other->node.port)
		return -1;
	if (self->node.port > other->node.port)
		return -1;

	res = strcmp(self->node.iface, other->node.iface);
	if (res)
		return res;

	return 0;
}

PyObject *PyIscsiNode_richcompare(PyIscsiNode *self, PyIscsiNode *other, int op)
{
    CMP_TO_RICHCMP(PyIscsiNode_compare)
}

static PyObject *PyIscsiNode_str(PyObject *self)
{
	PyIscsiNode *node = (PyIscsiNode *)self;
	char s[1024], tpgt[16] = "";

	if (node->node.tpgt != -1)
		sprintf(tpgt, ",%d", node->node.tpgt);

	snprintf(s, sizeof(s), "%s:%d%s %s", node->node.address,
		 node->node.port, tpgt, node->node.name);

	return PYSTR_FROMSTRING(s);
}

static PyObject *PyIscsiNode_login(PyObject *self)
{
	PyIscsiNode *node = (PyIscsiNode *)self;

	if (libiscsi_node_login(context, &node->node)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *PyIscsiNode_logout(PyObject *self)
{
	PyIscsiNode *node = (PyIscsiNode *)self;

	if (libiscsi_node_logout(context, &node->node)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *PyIscsiNode_setAuth(PyObject *self, PyObject *args,
				     PyObject *kwds)
{
	char *kwlist[] = {"authinfo", NULL};
	PyIscsiNode *node = (PyIscsiNode *)self;
	PyObject *arg;
	const struct libiscsi_auth_info *authinfo = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &arg))
		return NULL;

	if (arg == Py_None) {
		authinfo = NULL;
	} else if (PyObject_IsInstance(arg, (PyObject *)
				       &PyIscsiChapAuthInfo_Type)) {
		PyIscsiChapAuthInfo *pyauthinfo = (PyIscsiChapAuthInfo *)arg;
		authinfo = &pyauthinfo->info;
	} else {
		PyErr_SetString(PyExc_ValueError, "invalid authinfo type");
		return NULL;
	}

	if (libiscsi_node_set_auth(context, &node->node, authinfo)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *PyIscsiNode_getAuth(PyObject *self)
{
	PyIscsiNode *node = (PyIscsiNode *)self;
	PyIscsiChapAuthInfo *pyauthinfo;
	struct libiscsi_auth_info authinfo;

	if (libiscsi_node_get_auth(context, &node->node, &authinfo)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}

	switch (authinfo.method) {
	case libiscsi_auth_chap:
		pyauthinfo = PyObject_New(PyIscsiChapAuthInfo,
					  &PyIscsiChapAuthInfo_Type);
		if (!pyauthinfo)
			return NULL;

		pyauthinfo->info = authinfo;

		return (PyObject *)pyauthinfo;

	case libiscsi_auth_none:
	default:
		Py_RETURN_NONE;
	}
}

static PyObject *PyIscsiNode_setParameter(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	char *kwlist[] = {"parameter", "value", NULL};
	PyIscsiNode *node = (PyIscsiNode *)self;
	const char *parameter, *value;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist,
					 &parameter, &value))
		return NULL;
	if (check_string(parameter) || check_string(value))
		return NULL;

	if (libiscsi_node_set_parameter(context, &node->node, parameter,
				        value)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}
	Py_RETURN_NONE;
}

static PyObject *PyIscsiNode_getParameter(PyObject *self, PyObject *args,
					  PyObject *kwds)
{
	char *kwlist[] = {"parameter", NULL};
	PyIscsiNode *node = (PyIscsiNode *)self;
	const char *parameter;
	char value[LIBISCSI_VALUE_MAXLEN];

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &parameter))
		return NULL;
	if (check_string(parameter))
		return NULL;

	if (libiscsi_node_get_parameter(context, &node->node, parameter,
					value)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}
	return Py_BuildValue("s", value);
}

static struct PyGetSetDef PyIscsiNode_getseters[] = {
	{"name", (getter)PyIscsiNode_get, (setter)PyIscsiNode_set,
		"name", "name"},
	{"tpgt", (getter)PyIscsiNode_get, (setter)PyIscsiNode_set,
		"tpgt", "tpgt"},
	{"address", (getter)PyIscsiNode_get, (setter)PyIscsiNode_set,
		"address", "address"},
	{"port", (getter)PyIscsiNode_get, (setter)PyIscsiNode_set,
		"port", "port"},
	{"iface", (getter)PyIscsiNode_get, (setter)PyIscsiNode_set,
		"iface", "iface"},
	{NULL}
};

static struct PyMethodDef  PyIscsiNode_methods[] = {
	{"login", (PyCFunction) PyIscsiNode_login, METH_NOARGS,
		"Log in to the node"},
	{"logout", (PyCFunction) PyIscsiNode_logout, METH_NOARGS,
		"Log out of the node"},
	{"setAuth", (PyCFunction) PyIscsiNode_setAuth,
		METH_VARARGS|METH_KEYWORDS,
		"Set authentication information"},
	{"getAuth", (PyCFunction) PyIscsiNode_getAuth, METH_NOARGS,
		"Get authentication information"},
	{"setParameter", (PyCFunction) PyIscsiNode_setParameter,
		METH_VARARGS|METH_KEYWORDS,
		"Set an iscsi node parameter"},
	{"getParameter", (PyCFunction) PyIscsiNode_getParameter,
		METH_VARARGS|METH_KEYWORDS,
		"Get an iscsi node parameter"},
	{NULL}
};

PyTypeObject PyIscsiNode_Type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "libiscsi.node",
	.tp_basicsize = sizeof (PyIscsiNode),
	.tp_getset = PyIscsiNode_getseters,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE
#ifndef IS_PY3K
	| Py_TPFLAGS_CHECKTYPES
#endif
	,
	.tp_methods = PyIscsiNode_methods,
	.tp_richcompare = (richcmpfunc)PyIscsiNode_richcompare,
	.tp_init = PyIscsiNode_init,
	.tp_str = PyIscsiNode_str,
	.tp_new = PyType_GenericNew,
	.tp_doc = "The iscsi node contains iscsi node information.",
};

/***************************************************************************/

static PyObject *pylibiscsi_discover_sendtargets(PyObject *self,
						PyObject *args, PyObject *kwds)
{
	char *kwlist[] = {"address", "port", "authinfo", NULL};
	const char *address = NULL;
	int i, nr_found, port = 3260;
	PyObject *authinfo_arg = NULL;
	const struct libiscsi_auth_info *authinfo = NULL;
	struct libiscsi_node *found_nodes;
	PyObject* found_node_list;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|iO",
					kwlist, &address, &port,
					&authinfo_arg))
		return NULL;

	if (authinfo_arg) {
		if (PyObject_IsInstance(authinfo_arg, (PyObject *)
					       &PyIscsiChapAuthInfo_Type)) {
			PyIscsiChapAuthInfo *pyauthinfo =
				(PyIscsiChapAuthInfo *)authinfo_arg;
			authinfo = &pyauthinfo->info;
		} else if (authinfo_arg != Py_None) {
			PyErr_SetString(PyExc_ValueError,
				"invalid authinfo type");
			return NULL;
		}
	}

	if (libiscsi_discover_sendtargets(context, address, port, authinfo,
					  &nr_found, &found_nodes)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}

	if (nr_found == 0)
		Py_RETURN_NONE;

	found_node_list = PyList_New(nr_found);
	if (!found_node_list)
		return NULL;

	for(i = 0; i < nr_found; i++) {
		PyIscsiNode *pynode;

		pynode = PyObject_New(PyIscsiNode, &PyIscsiNode_Type);
		if (!pynode) {
			/* This will deref already added nodes for us */
			Py_DECREF(found_node_list);
			return NULL;
		}
		pynode->node = found_nodes[i];
		PyList_SET_ITEM(found_node_list, i, (PyObject *)pynode);
	}

	return found_node_list;
}

static PyObject *pylibiscsi_discover_firmware(PyObject *self)
{
	int i, nr_found;
	struct libiscsi_node *found_nodes;
	PyObject* found_node_list;

	if (libiscsi_discover_firmware(context, &nr_found, &found_nodes)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}

	if (nr_found == 0)
		Py_RETURN_NONE;

	found_node_list = PyList_New(nr_found);
	if (!found_node_list)
		return NULL;

	for(i = 0; i < nr_found; i++) {
		PyIscsiNode *pynode;

		pynode = PyObject_New(PyIscsiNode, &PyIscsiNode_Type);
		if (!pynode) {
			/* This will deref already added nodes for us */
			Py_DECREF(found_node_list);
			return NULL;
		}
		pynode->node = found_nodes[i];
		PyList_SET_ITEM(found_node_list, i, (PyObject *)pynode);
	}

	return found_node_list;
}

static PyObject *pylibiscsi_get_firmware_initiator_name(PyObject *self)
{
	char initiatorname[LIBISCSI_VALUE_MAXLEN];

	if (libiscsi_get_firmware_initiator_name(initiatorname)) {
		PyErr_SetString(PyExc_IOError,
				libiscsi_get_error_string(context));
		return NULL;
	}

	return PYSTR_FROMSTRING(initiatorname);
}

static PyMethodDef pylibiscsi_functions[] = {
	{	"discover_sendtargets",
		(PyCFunction)pylibiscsi_discover_sendtargets,
		METH_VARARGS|METH_KEYWORDS,
		"Do sendtargets discovery and return a list of found nodes)"},
	{	"discover_firmware",
		(PyCFunction)pylibiscsi_discover_firmware, METH_NOARGS,
		"Do firmware discovery and return a list of found nodes)"},
	{	"get_firmware_initiator_name",
		(PyCFunction)pylibiscsi_get_firmware_initiator_name,
		METH_NOARGS,
		"Get initator name (iqn) from firmware"},
	{NULL, NULL}
};

#ifdef IS_PY3K
static struct PyModuleDef libiscsi_def = {
	PyModuleDef_HEAD_INIT,
	"libiscsi",
	NULL,
	-1,
	pylibiscsi_functions,
	NULL,
	NULL,
	NULL,
	NULL
};

PyMODINIT_FUNC PyInit_libiscsi(void)
#else
PyMODINIT_FUNC initlibiscsi(void)
#endif
{
	PyObject *m;

	if (!context) /* We may be called more then once */
		context = libiscsi_init();
	if (!context)
		MODINITERROR;

	if (PyType_Ready(&PyIscsiChapAuthInfo_Type) < 0)
		MODINITERROR;

	if (PyType_Ready(&PyIscsiNode_Type) < 0)
		MODINITERROR;

#ifdef IS_PY3K
	m = PyModule_Create(&libiscsi_def);
#else
	m = Py_InitModule("libiscsi", pylibiscsi_functions);
#endif
	Py_INCREF(&PyIscsiChapAuthInfo_Type);
	PyModule_AddObject(m, "chapAuthInfo", (PyObject *)
			   &PyIscsiChapAuthInfo_Type);
	Py_INCREF(&PyIscsiNode_Type);
	PyModule_AddObject(m, "node", (PyObject *) &PyIscsiNode_Type);
#ifdef IS_PY3K
	return m;
#endif
}
