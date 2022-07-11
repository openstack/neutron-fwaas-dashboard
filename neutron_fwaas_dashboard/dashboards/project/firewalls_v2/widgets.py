#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import itertools

from django.template.loader import get_template
from django.utils.translation import gettext_lazy as _
from horizon.forms import fields

"""A custom Horizon Forms Select widget that displays select choices as a table

The widgets is meant as an optional replacement for the existing Horizon
ThemableDynamicSelectWidget which it extends and is compatible with.


Columns
-------
Columns are defined by setting the widgets 'column' attribute, which is
expected to be an iterable of strings, each one corresponding to one column and
used for that columns heading.


Rows
----
Each row corresponds to one choice/select option with a defined value in
each column.

The values displayed in each column are derived using the 'build_columns'
attribute, which is expected to be a function that:

- takes a choice tuple of the form (value, label) as defined
  for the Django SelectField instances as it's only parameter
- returns an iterable of Strings which are rendered as column
  values for the given choice row in the same order as in the
  iterable

The default implementation simply uses the provided value and label as separate
column values.

See the default implementation and example bellow for more details.


Condensed values
----------------
To maintain visual consistency, the currently selected value is displayed in
the 'standard' ThemableDynamicSelectWidget HTML setup. To accommodate this, a
condensed, single string value is created from the individual columns and
displayed in the select box.

This behavior can be modified by setting the 'condense' attribute. This is
expected to be a function that:

- Takes the column iterable returned by 'build_columns' function
- Returns a single string representation of the choice

By default, the condensed value is created by joining all of the provided
columns and joining them using commas as a delimiter.

See the default implementation and example bellow for more details.


Small screen reactivity
-----------------------
Support for small screens (< 768px) is turned on by setting the attribute
'alternate_xs' to True. When on, a condesned version of the popup table
us used for small screens, where a single column is used with the condensed
row values used instead of the full table rows.

The 'condense' function described above is used to construct this table.


Example
-------

port_id = forms.ThemableDynamicChoiceField(
    label=_("Ports"),
    widget=TableSelectWidget(
        columns=[
            'ID',
            'Name'
        ],
        build_columns=lambda choice: return (choice[1], choice[0]),
        choices=[
            ('port 1', 'id1'),
            ('port 2', 'id2')
        ],
        alternate_xs=True,
        condense=lambda columns: return ",".join(columns)
    )
)

Produces:

+------+--------+
|  ID  |  Name  |
+------+--------+
| id1  | port 1 |
| id2  | port 2 |
+------+--------+

on normal screens and

+-------------+
|  ID, Name   |
+-------------+
| id1, port 1 |
| id2, port 2 |
+-------------+

on xs screens.

"""


class TableSelectWidget(fields.ThemableDynamicSelectWidget):
    def __init__(self,
                 attrs=None,
                 columns=None,
                 alternate_xs=False,
                 empty_text=_("No options available"),
                 other_html=None,
                 condense=None,
                 build_columns=None, *args, **kwargs
                 ):
        """Initializer for TableSelectWidget

        :param attrs: A { attribute: value } dictionary which is attached to
                      the hidden select element; see
                      ThemableDynamicSelectWidget for further information
        :param columns: An iterable of column headers/names
        :param alternate_xs: A truth-y value which enables/disables an
                             alternate rendering method for small screens
        :param empty_text: The text to be displayed in case no options are
                           available
        :param other_html: A method for adding custom HTML to the hidden option
                           HTML.
                           NOTE: This mimics the behavior of
                           ThemableDynamicSelectWidget and is retained to
                           maintain compatibility with any related, potential
                           functionality
        :param condense: A function callback that produces a condensed label
                         for each option
        :param build_columns: A function used to populate the individual
                              columns in the pop up table for each option
        """
        super(TableSelectWidget, self).__init__(attrs, *args, **kwargs)
        self.columns = columns or [_('Label'), _('Value'), 'Nothing']

        self.alternate_xs = alternate_xs
        self.empty_text = empty_text

        if other_html:
            self.other_html = other_html

        if condense:
            self.condense = condense

        if build_columns:
            self.build_columns = build_columns

    @staticmethod
    def build_columns(choice):
        """Default column building method

        Overwrite this method when initializing this widget or using
        self.fields[name].widget.build_columns in a parent form initialization
        to customize the behavior (see above for details)

        :param choice:
        :return:
        """
        return choice

    @staticmethod
    def condense(choice_columns):
        """The default condense method

        Overwrite this method when initializing this widget or using
        self.fields[name].widget.condense in a parent form initialization to
        customize the behavior (see above for details)

        :param choice_columns:
        :return:
        """
        return " / ".join([str(c) for c in choice_columns])

    # Implements the parent 'other_html' construction for compatibility reasons
    # Can be set in initializer to change the behavior as needed
    def other_html(self, choice):
        opt_label = choice[1]

        other_html = self.transform_option_html_attrs(opt_label)
        data_attr_html = self.get_data_attrs(opt_label)

        if data_attr_html:
            other_html += ' ' + data_attr_html

        return other_html

    def render(self, name, value, attrs=None, choices=None, renderer=None):
        new_choices = []
        initial_value = value

        choices = choices or []

        for opt in itertools.chain(self.choices, choices):
            other_html = self.other_html(opt)
            choice_columns = self.build_columns(opt)
            condensed_label = self.condense(choice_columns)

            built_choice = (
                opt[0], condensed_label, choice_columns, other_html
            )

            new_choices.append(built_choice)

            # Initial selection
            if opt[0] == value:
                initial_value = built_choice

        if not initial_value and new_choices:
            initial_value = new_choices[0]

        element_id = attrs.pop('id', 'id_%s' % name)

        # Size of individual columns in terms of the bootstrap grid - used
        # for styling purposes
        column_size = 12 // len(self.columns)

        # Creates a single string label for all columns for use with small
        # screens
        condensed_headers = self.condense(self.columns)

        template = get_template('project/firewalls_v2/table_select.html')

        select_attrs = self.build_attrs(attrs)

        context = {
            'name': name,
            'options': new_choices,
            'id': element_id,
            'value': value,
            'initial_value': initial_value,
            'select_attrs': select_attrs,
            'column_size': column_size,
            'columns': self.columns,
            'condensed_headers': condensed_headers,
            'alternate_xs': self.alternate_xs,
            'empty_text': self.empty_text
        }
        return template.render(context)
