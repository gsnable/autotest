import  sys, re, subprocess
from cse.course_configuration import course_configuration

# return a pair of hashes
# 1 mapping labs to a list of tutors
# 2 mapping tutors to list of labs

def get_tutor_timetable():
    lab_to_tutors = {}
    tutor_to_labs = {}
    security_file = course_configuration['sms_directory']+"/security"
    with open(security_file) as f:
        for line in f:
            (account, ignore, lab) = line.strip().split("|")[0:3]
            zid = get_zid(account)
            if zid:
                if lab in lab_to_tutors:
                    lab_to_tutors[lab].append(zid)
                else:
                    lab_to_tutors[lab] = [zid]
                if zid in tutor_to_labs:
                    tutor_to_labs[zid].append(lab)
                else:
                    tutor_to_labs[zid] = [lab]
            else:
                print('No zid for tutor:', account)
    return (lab_to_tutors, tutor_to_labs)

def get_students_tutlab(courses):
    enrollments_file = "/home/teachadmin/lib/enrollments/%s_COMP" % course_configuration['unsw_session']
    students_tutlab = {}
    for line in open(enrollments_file,encoding='latin1'):
        field = line.strip().split("|")
        if field[0] in courses:
            tlb = field[9].strip()
            if not tlb.startswith('HS'):
                students_tutlab['z'+field[1]] = tlb
    return students_tutlab

#
def get_zid(account=None):
    if account:
        m = re.search(r'\bz?(\d{7})$', account)
        if m:
            return 'z' + m.group(1)
    command = ['acc']
    if account:
        command += [account]
    try:
#        print(" ".join(command))
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        m = re.search(r'\bz?(\d{7})\b', output)
        if m:
            return 'z' + m.group(1)
    except subprocess.CalledProcessError:
        pass

def get_name_account(account=None):
    return subprocess.check_output(['acc', 'format=$name', account], universal_newlines=True).strip()

def get_exercise_name(parameters):
    exercise_name = parameters.getvalue('exercise_name', '')
    if not exercise_name:
        print('Error: missing exercise_name')
        sys.exit(0)
    exercise_name = re.sub(r'[^\w\-\./]', '', exercise_name)
    fields = exercise_name.split('/')
    if len(fields) != 2:
        print('Error:invalid exercise_name')
        sys.exit(0)
    for f in fields:
        if not f or f[0] == '.':
            print('Error: invalid exercise_name')
            sys.exit(0)
    return fields
