#!/usr/bin/env python
import sys

import ldif

class Dumper(ldif.LDIFParser):
    def __init__(self, input_file, reserved_file, min_year=2017, **kwargs):
        ldif.LDIFParser.__init__(self, input_file, **kwargs)

        self.imported = 0
        self.skipped = 0
        self.reserved_file = reserved_file
        self.min_year = min_year

    def run(self):
        self.parse_entry_records()

        print(f'imported {self.imported} users, skipped {self.skipped}')

    def handle_modify(self, dn, modops, controls=None):
        raise NotImplementedError

    @staticmethod
    def _utf8ify(values):
        return map(lambda v: v.decode('utf-8'), values)
    @staticmethod
    def _item_or_list(value):
        assert value
        if len(value) == 1:
            return value[0]
        return value
    @staticmethod
    def _filter_entry(entry):
        new_entry = {}
        for attr, values in entry.items():
            if attr.lower() == 'objectclass':
                attr = 'objectclass'
                values = set(Dumper._utf8ify(values))
            else:
                values = Dumper._item_or_list(list(Dumper._utf8ify(values)))
            new_entry[attr] = values
        return new_entry
    def handle(self, dn, entry):
        u = Dumper._filter_entry(entry)
        if 'tcdnetsoc-person' not in u['objectclass']:
            return

        uid = u['uid']
        if uid.startswith('user') and 'tcdnetsoc-ISS-username' in u:
            print(f'weird u: {uid}', file=sys.stderr)
        if 'tcdnetsoc-admin-comment' in u:
            for comment in u['tcdnetsoc-admin-comment']:
                if comment.startswith('Deleted'):
                    self.skipped += 1
                    return
        if 'tcdnetsoc-saved-password' in u and u['tcdnetsoc-saved-password'] == '***newmember***':
            print(f'warning: deleting "new member" {uid}')
            self.skipped += 1
            return
        if 'tcdnetsoc-ISS-username' not in u:
            print(f'warning: skipping {uid} who has no TCD username')
            self.skipped += 1
            return
        if 'tcdnetsoc-membership-year' not in u:
            print(f'warning: skipping {uid} who has no membership years')
            self.skipped += 1
            return

        years = u['tcdnetsoc-membership-year']
        if isinstance(years, str):
            years = [years]

        years = list(sorted(map(int, map(lambda y: y[:4], years))))
        if years[-1] < self.min_year:
            print(f'warning: skipping {uid} who has not renewed since before {self.min_year}')
            self.skipped += 1
            return

        print(f'reserving username {uid}')
        print(uid, file=self.reserved_file)
        self.imported += 1

def main():
    if len(sys.argv) != 4:
        print(f'usage: {sys.argv[0]} <dump.ldif> <reserved.txt> <min_year>', file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as dump_file:
        with open(sys.argv[2], 'w') as reserved_file:
            dumper = Dumper(dump_file, reserved_file, min_year=int(sys.argv[3]))
            dumper.run()

if __name__ == '__main__':
    main()
