# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import annotations

DOCUMENTATION = """
    name: please
    short_description: please, a sudo clone
    description:
        - This become plugin allows your remote/login user to execute commands as another user via the please utility.
    author: hyperglue (based on ansible.builtin.su)
    options:
        become_user:
            description: User you 'become' to execute the task
            default: root
            ini:
              - section: privilege_escalation
                key: become_user
              - section: please_become_plugin
                key: user
            vars:
              - name: ansible_become_user
              - name: ansible_please_user
            env:
              - name: ANSIBLE_BECOME_USER
              - name: ANSIBLE_PLEASE_USER
            keyword:
              - name: become_user
        become_exe:
            description: please executable
            default: please
            ini:
              - section: privilege_escalation
                key: become_exe
              - section: please_become_plugin
                key: executable
            vars:
              - name: ansible_become_exe
              - name: ansible_please_exe
            env:
              - name: ANSIBLE_BECOME_EXE
              - name: ANSIBLE_PLEASE_EXE
            keyword:
              - name: become_exe
        become_flags:
            description: Options to pass to please
            default: ''
            ini:
              - section: privilege_escalation
                key: become_flags
              - section: please_become_plugin
                key: flags
            vars:
              - name: ansible_become_flags
              - name: ansible_please_flags
            env:
              - name: ANSIBLE_BECOME_FLAGS
              - name: ANSIBLE_PLEASE_FLAGS
            keyword:
              - name: become_flags
        become_pass:
            description: Password to pass to please
            required: False
            vars:
              - name: ansible_become_password
              - name: ansible_become_pass
              - name: ansible_please_pass
            env:
              - name: ANSIBLE_BECOME_PASS
              - name: ANSIBLE_PLEASE_PASS
            ini:
              - section: please_become_plugin
                key: password
        prompt_l10n:
            description:
                - List of localized strings to match for prompt detection
                - If empty we'll use the built in one
                - Do NOT add a colon (:) to your custom entries. Ansible adds a colon at the end of each prompt;
                  if you add another one in your string, your prompt will fail with a "Timeout" error.
            default: []
            type: list
            elements: string
            ini:
              - section: please_become_plugin
                key: localized_prompts
            vars:
              - name: ansible_please_prompt_l10n
            env:
              - name: ANSIBLE_PLEASE_PROMPT_L10N
"""

import re
import shlex

from ansible.module_utils.common.text.converters import to_bytes
from ansible.plugins.become import BecomeBase


class BecomeModule(BecomeBase):

    name = 'please'

    # messages for detecting prompted password issues
    fail = ('Authentication failed :-(',)

    PLEASE_PROMPT_LOCALIZATIONS = [
        '\[please\]\ password.*',
    ]

    def check_password_prompt(self, b_output):
        ''' checks if the expected password prompt exists in b_output '''

        prompts = self.get_option('prompt_l10n') or self.PLEASE_PROMPT_LOCALIZATIONS
        b_password_string = b"|".join((br'(\w+\'s )?' + to_bytes(p)) for p in prompts)
        # Colon or unicode fullwidth colon
        b_password_string = b_password_string + to_bytes(u' ?(:|：) ?')
        b_please_prompt_localizations_re = re.compile(b_password_string, flags=re.IGNORECASE)
        return bool(b_please_prompt_localizations_re.match(b_output))

    def build_become_command(self, cmd, shell):
        super(BecomeModule, self).build_become_command(cmd, shell)

        # Prompt handling for ``please`` is more complicated, this
        # is used to satisfy the connection plugin
        self.prompt = True

        if not cmd:
            return cmd

        exe = self.get_option('become_exe') or self.name
        flags = self.get_option('become_flags') or ''
        user = self.get_option('become_user') or ''
        success_cmd = self._build_success_command(cmd, shell)

        return "%s %s -u %s %s" % (exe, flags, user, success_cmd)
