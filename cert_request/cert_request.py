"""TO-DO: Write a description of what this XBlock is."""

import pkg_resources
import json
from collections import defaultdict

from xblock.core import XBlock
from xblock.fields import Scope, String, Integer
from xblock.exceptions import JsonHandlerError
from xblock.fragment import Fragment
from mako.template import Template
#from courseware.views import generate_user_cert
from django.contrib.auth.models import User
from certificates import api as certs_api
from opaque_keys.edx.keys import CourseKey
from courseware.courses import get_course_by_id
from courseware.views import is_course_passed
from courseware.model_data import FieldDataCache, ScoresClient
from functools import partial
#from courseware.grades import field_data_cache_for_grading
from util.module_utils import yield_dynamic_descriptor_descendants
from courseware.access import has_access
from xmodule.graders import Score
from xmodule import graders
from courseware.module_render import get_module_for_descriptor
from courseware.courses import (
    get_courses,
    get_course,
    get_course_by_id,
    get_permission_for_course_about,
    get_studio_url,
    get_course_overview_with_access,
    get_course_with_access,
    sort_by_announcement,
    sort_by_start_date,
    UserNotEnrolled
)
from courseware import grades
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from certificates.queue import XQueueCertInterface
from certificates.models import GeneratedCertificate, CertificateStatuses
from certificates.api import has_html_certificates_enabled
from student.models import UserProfile, CourseEnrollment
from lms.djangoapps.verify_student.models import SoftwareSecurePhotoVerification
from capa.xqueue_interface import make_xheader, make_hashkey
import random
from uuid import uuid4
from course_blocks.api import get_course_blocks
#from block_structure.api import get_course_in_cache
from submissions import api as sub_api
from student.models import anonymous_id_for_user
from courseware.models import StudentModule
from django.conf import settings
from django.core.cache import cache
from util.db import outer_atomic

def descriptor_affects_grading(block_types_affecting_grading, descriptor):
        """
        Returns True if the descriptor could have any impact on grading, else False.
        Something might be a scored item if it is capable of storing a score
        (has_score=True). We also have to include anything that can have children,
        since those children might have scores. We can avoid things like Videos,
                        which have state but cannot ever impact someone's grade.
        """
        return descriptor.location.block_type in block_types_affecting_grading






def field_data_cache_for_grading(course, user):
        """
        Given a CourseDescriptor and User, create the FieldDataCache for grading.
        This will generate a FieldDataCache that only loads state for those things
        that might possibly affect the grading process, and will ignore things like
        Videos.
        """
        descriptor_filter = partial(descriptor_affects_grading, course.block_types_affecting_grading)
        return FieldDataCache.cache_for_descriptor_descendents(
                course.id,
                user,
                course,
                depth=None,
                descriptor_filter=descriptor_filter
        )






def get_score(user, problem_descriptor, module_creator, scores_client, submissions_scores_cache, max_scores_cache):
    """
    Return the score for a user on a problem, as a tuple (correct, total).
    e.g. (5,7) if you got 5 out of 7 points.
    If this problem doesn't have a score, or we couldn't load it, returns (None,
    None).
    user: a Student object
    problem_descriptor: an XModuleDescriptor
    scores_client: an initialized ScoresClient
    module_creator: a function that takes a descriptor, and returns the corresponding XModule for this user.
           Can return None if user doesn't have access, or if something else went wrong.
    submissions_scores_cache: A dict of location names to (earned, possible) point tuples.
           If an entry is found in this cache, it takes precedence.
    max_scores_cache: a MaxScoresCache
    """
    submissions_scores_cache = submissions_scores_cache or {}

    if not user.is_authenticated():
        return (None, None)

    location_url = problem_descriptor.location.to_deprecated_string()
    if location_url in submissions_scores_cache:
        return submissions_scores_cache[location_url]

    # some problems have state that is updated independently of interaction
    # with the LMS, so they need to always be scored. (E.g. combinedopenended ORA1.)
    if problem_descriptor.always_recalculate_grades:
        problem = module_creator(problem_descriptor)
        if problem is None:
            return (None, None)
        score = problem.get_score()
        if score is not None:
            return (score['score'], score['total'])
        else:
            return (None, None)

    if not problem_descriptor.has_score:
        # These are not problems, and do not have a score
        return (None, None)

    # Check the score that comes from the ScoresClient (out of CSM).
    # If an entry exists and has a total associated with it, we trust that
    # value. This is important for cases where a student might have seen an
    # older version of the problem -- they're still graded on what was possible
    # when they tried the problem, not what it's worth now.
    score = scores_client.get(problem_descriptor.location)
    cached_max_score = max_scores_cache.get(problem_descriptor.location)
    print "score===========",score
    if score and score.total is not None:
        # We have a valid score, just use it.
        correct = score.correct if score.correct is not None else 0.0
        total = score.total
    elif cached_max_score is not None and settings.FEATURES.get("ENABLE_MAX_SCORE_CACHE"):
        # We don't have a valid score entry but we know from our cache what the
        # max possible score is, so they've earned 0.0 / cached_max_score
        correct = 0.0
        total = cached_max_score
    else:
        # This means we don't have a valid score entry and we don't have a
        # cached_max_score on hand. We know they've earned 0.0 points on this,
        # but we need to instantiate the module (i.e. load student state) in
        # order to find out how much it was worth.
        problem = module_creator(problem_descriptor)
        if problem is None:
            return (None, None)

        correct = 0.0
        total = problem.max_score()

        # Problem may be an error module (if something in the problem builder failed)
        # In which case total might be None
        if total is None:
            return (None, None)
        else:
            # add location to the max score cache
            max_scores_cache.set(problem_descriptor.location, total)

    return weighted_score(correct, total, problem_descriptor.weight)

def get_grades(course,student):
	
	
	field_data_cache = field_data_cache_for_grading(course, student)
	scores_client = ScoresClient.from_field_data_cache(field_data_cache)

	grading_context = course.grading_context
    	raw_scores = []
	keep_raw_scores = None

   	 # Dict of item_ids -> (earned, possible) point tuples. This *only* grabs
    	 # scores that were registered with the submissions API, which for the moment
    	 # means only openassessment (edx-ora2)
    	submissions_scores = sub_api.get_scores(
            course.id.to_deprecated_string(),
            anonymous_id_for_user(student, course.id)
        )
        max_scores_cache = MaxScoresCache.create_for_course(course)

        # For the moment, we have to get scorable_locations from field_data_cache
        # and not from scores_client, because scores_client is ignorant of things
        # in the submissions API. As a further refactoring step, submissions should
        # be hidden behind the ScoresClient.
	max_scores_cache.fetch_from_remote(field_data_cache.scorable_locations)

    	totaled_scores = {}
	graded_total = []
    	# This next complicated loop is just to collect the totaled_scores, which is
    	# passed to the grader
    	for section_format, sections in grading_context['graded_sections'].iteritems():
       		format_scores = []
        	for section in sections:
            		section_descriptor = section['section_descriptor']
            		section_name = section_descriptor.display_name_with_default

            		# some problems have state that is updated independently of interaction
            		# with the LMS, so they need to always be scored. (E.g. foldit.,
            		# combinedopenended)
            		should_grade_section = any(
                		descriptor.always_recalculate_grades for descriptor in section['xmoduledescriptors']
            		)

            		# If there are no problems that always have to be regraded, check to
            		# see if any of our locations are in the scores from the submissions
            		# API. If scores exist, we have to calculate grades for this section.
            		if not should_grade_section:
                		should_grade_section = any(
                    			descriptor.location.to_deprecated_string() in submissions_scores
                    			for descriptor in section['xmoduledescriptors']
                		)

            		if not should_grade_section:
                		
				should_grade_section = any(
                        					descriptor.location in scores_client
                        					for descriptor in section['xmoduledescriptors']
							)
            		# If we haven't seen a single problem in the section, we don't have
            		# to grade it at all! We can assume 0%
            		if should_grade_section:
                		scores = []

                		def create_module(descriptor):
                    			'''creates an XModule instance given a descriptor'''
                    			#TODO: We need the request to pass into here. If we could forego that, our arguments
                    			# would be simpler
                    			
                        		pass

                		for module_descriptor in yield_dynamic_descriptor_descendants(section_descriptor, student.id, create_module):
					(correct, total) = get_score(
                            					student,
                            					module_descriptor,
                            					create_module,
                            					scores_client,
                            					submissions_scores,
                            					max_scores_cache,
							   )
					print "total==============",total
					print "correct================",correct
                    			if correct is None and total is None:
                        			continue

                        		if settings.GENERATE_PROFILE_SCORES:  	# for debugging!
                        			if total > 1:
                            				correct = random.randrange(max(total - 2, 1), total + 1)
                       	        		else:
                            				correct = total

                    			graded = module_descriptor.graded
                    			if not total > 0:
                        		#We simply cannot grade a problem that is 12/0, because we might need it as a percentage
                        			graded = False

                    			#scores.append(Score(correct, total, graded, module_descriptor.display_name_with_default))
					scores.append(Score(correct,total,graded,module_descriptor.display_name_with_default,module_descriptor.location))

                			_, graded_total = graders.aggregate_scores(scores, section_name)
                			if keep_raw_scores:
                    				raw_scores += scores
            		else:
            			graded_total = Score(0.0, 1.0, True, section_name,None)

            			#Add the graded total to totaled_scores
			if graded_total:
            			if graded_total.possible > 0:
                			format_scores.append(graded_total)
            			else:
                			log.info("Unable to grade a section with a total possible score of zero. " +
                              		str(section_descriptor.location))
		totaled_scores[section_format] = format_scores

    	grade_summary = course.grader.grade(totaled_scores, generate_random_scores=settings.GENERATE_PROFILE_SCORES)

    	# We round the grade here, to make sure that the grade is an whole percentage and
    	# doesn't get displayed differently than it gets grades
    	grade_summary['percent'] = round(grade_summary['percent'] * 100 + 0.05) / 100

    	letter_grade = grade_for_percentage(course.grade_cutoffs, grade_summary['percent'])
    	grade_summary['grade'] = letter_grade
    	grade_summary['totaled_scores'] = totaled_scores  	# make this available, eg for instructor download & debugging
    	if keep_raw_scores:
        	grade_summary['raw_scores'] = raw_scores        # way to get all RAW scores out to instructor
        
	max_scores_cache.push_to_remote()                                                # so grader can be double-checked
	return grade_summary





def generate_user_certificates(student, course_key, course=None, insecure=False, generation_mode='batch',
                               forced_grade=None):
    """
    It will add the add-cert request into the xqueue.
    A new record will be created to track the certificate
    generation task.  If an error occurs while adding the certificate
    to the queue, the task will have status 'error'. It also emits
    `edx.certificate.created` event for analytics.
    Args:
        student (User)
        course_key (CourseKey)
    Keyword Arguments:
        course (Course): Optionally provide the course object; if not provided
            it will be loaded.
        insecure - (Boolean)
        generation_mode - who has requested certificate generation. Its value should `batch`
        in case of django command and `self` if student initiated the request.
        forced_grade - a string indicating to replace grade parameter. if present grading
                       will be skipped.
    """
    template_file = None
    course_id  = course.id   
    enrollment_mode, __ = CourseEnrollment.enrollment_mode_for_user(student, course_id)
    mode_is_verified = enrollment_mode in GeneratedCertificate.VERIFIED_CERTS_MODES
    user_is_verified = SoftwareSecurePhotoVerification.user_is_verified(student)
    cert_mode = enrollment_mode

    if template_file is not None:
            template_pdf = template_file
    elif mode_is_verified and user_is_verified:
            template_pdf = "certificate-template-{id.org}-{id.course}-verified.pdf".format(id=course_id)
    elif mode_is_verified and not user_is_verified:
  	    template_pdf = "certificate-template-{id.org}-{id.course}.pdf".format(id=course_id) 
  	    if CourseMode.mode_for_course(course_id, CourseMode.HONOR):
          	  cert_mode = GeneratedCertificate.MODES.honor
            else:
            	  unverified = True
    else:
            # honor code and audit students
            template_pdf = "certificate-template-{id.org}-{id.course}.pdf".format(id=course_id)




    profile = UserProfile.objects.get(user=student)
    profile_name = profile.name

    cert, created = GeneratedCertificate.objects.get_or_create(user=student, course_id=course_id)  # pylint: disable=no-member



    grading_policy = get_grades(course,student)
    cert.mode = cert_mode
    cert.user = student
    cert.grade = grading_policy['percent']
    cert.course_id = course_id
    cert.name = profile_name
    cert.download_url = ''
    
    passing = True

    return _generate_cert(cert, course, student, False, template_pdf)


def _generate_cert(cert, course, student, grade_contents, template_pdf):
        """
        Generate a certificate for the student. If `generate_pdf` is True,
        sends a request to XQueue.
        """
        course_id = unicode(course.id)

        key = make_hashkey(random.random())
        cert.key = key
        contents = {
            'action': 'create',
            'username': student.username,
            'course_id': course_id,
            'course_name': course.display_name or course_id,
            'name': cert.name,
            'grade': grade_contents,
            'template_pdf': template_pdf,
        }
        cert.status = CertificateStatuses.downloadable
        cert.verify_uuid = uuid4().hex

        cert.save()
	return cert






def weighted_score(raw_correct, raw_total, weight):
    """Return a tuple that represents the weighted (correct, total) score."""
    # If there is no weighting, or weighting can't be applied, return input.
    if weight is None or raw_total == 0:
        return (raw_correct, raw_total)
    return (float(raw_correct) * weight / raw_total, float(weight))



class MaxScoresCache(object):

	def __init__(self, cache_prefix):
	        self.cache_prefix = cache_prefix
        	self._max_scores_cache = {}
        	self._max_scores_updates = {}

    	@classmethod
    	def create_for_course(cls, course):
		if course.subtree_edited_on is None:
            		# check for subtree_edited_on because old XML courses doesn't have this attribute
            		cache_key = u"{}".format(course.id)
        	else:
            		cache_key = u"{}.{}".format(course.id, course.subtree_edited_on.isoformat())
        	return cls(cache_key)

	def push_to_remote(self):
        	"""
        	Update the remote cache
       	        """
        	if self._max_scores_updates:
            		cache.set_many(
                		{
                    			self._remote_cache_key(key): value
                    			for key, value in self._max_scores_updates.items()
                		},
                		60 * 60 * 24  # 1 day
            		)

    	def _remote_cache_key(self, location):
        	"""Convert a location to a remote cache key (add our prefixing)."""
        	return u"grades.MaxScores.{}___{}".format(self.cache_prefix, unicode(location))

    	def _local_cache_key(self, remote_key):
        	"""Convert a remote cache key to a local cache key (i.e. location str)."""
        	return remote_key.split(u"___", 1)[1]

    	def num_cached_from_remote(self):
        	"""How many items did we pull down from the remote cache?"""
        	return len(self._max_scores_cache)

    	def num_cached_updates(self):
        	"""How many local updates are we waiting to push to the remote cache?"""
        	return len(self._max_scores_updates)

    	def set(self, location, max_score):
        	"""
        	Adds a max score to the max_score_cache
		"""
		loc_str = unicode(location)
       		if self._max_scores_cache.get(loc_str) != max_score:
            		self._max_scores_updates[loc_str] = max_score

    	def get(self, location):
        	"""
       		 Retrieve a max score from the cache
        	"""
       		loc_str = unicode(location)
        	max_score = self._max_scores_updates.get(loc_str)
        	if max_score is None:
            		max_score = self._max_scores_cache.get(loc_str)
        	return max_score

	def fetch_from_remote(self, locations):
       		 """
        	 Populate the local cache with values from django's cache
       		 """
        	 remote_dict = cache.get_many([self._remote_cache_key(loc) for loc in locations])
       		 self._max_scores_cache = {
            			self._local_cache_key(remote_key): value
            			for remote_key, value in remote_dict.items()
           	        	if value is not None
			}

class CertRequestXBlock(XBlock):
   
#    student = None
#    course = None	

    @XBlock.json_handler
    def generate_user_cert_xblock(self, data, suffix=''):
        

	student_id = self.scope_ids.user_id
        course_id = str(self.xmodule_runtime.course_id)
        course_key = CourseKey.from_string(course_id)
        student = User.objects.prefetch_related("groups").get(id=student_id)
        course = get_course_with_access(student, 'load', course_key, depth=None, check_if_enrolled=True)


	generate_user_certificates(student, course.id, course=course, generation_mode='self')
	return True





 
    display_name = String(
        default='On Demand Certificate', scope=Scope.settings,
        help="This name appears in the horizontal navigation at the top of "
             "the page.",
    )
    
    def resource_string(self, path):
        """Handy helper for getting resources from our kit."""
        data = pkg_resources.resource_string(__name__, path)
        return data.decode("utf8")
    
    def render_template(self, template_path, context={}):
        """
        Evaluate a template by resource path, applying the provided context
        """
        template_str = self.resource_string(template_path)
        template = Template(template_str)
        return template.render(**context)


    # TO-DO: change this view to display your data your own way.
    def student_view(self, context=None):
        """
        Redirect to author view when viewing in studio
        """
        if getattr(self.runtime, 'is_author_mode', False):
            return self.author_view()

        context = {}
        certificate_status = self.get_cert_status()
        context.update(certificate_status)

        #html = self.resource_string("static/html/cert_request.html")
        frag = Fragment()
        frag.add_content(
            self.render_template(
                'static/html/cert_request.html', context
            )
        )
        frag.add_css(self.resource_string("static/css/cert_request.css"))
        frag.add_javascript(self.resource_string("static/js/src/cert_request.js"))
        frag.initialize_js('CertRequestXBlock')
        return frag


    def studio_view(self, context):
        """
        Create a fragment used to display the edit view in the Studio.
        """
        html_str = self.resource_string("static/html/cert_request_edit.html")
        display_name = self.display_name or ''
        frag = Fragment(unicode(html_str).format(display_name=display_name))
        frag.add_javascript(self.resource_string("static/js/src/cert_request_edit.js"))
        frag.initialize_js('CertEditBlock')

        return frag

    def author_view(self, context=None):
        html_str = self.resource_string("static/html/cert_request_studio.html")
        display_name = self.display_name or ''
        frag = Fragment(unicode(html_str).format(display_name=display_name))
        return frag

    @XBlock.json_handler
    def studio_submit(self, data, suffix=''):
        """
        Called when submitting the form in Studio.
        """
        self.display_name = data.get('display_name')

        return {'result': 'success'}




    


    def get_cert_status(self):
        student_id = self.scope_ids.user_id
        course_id = str(self.xmodule_runtime.course_id)
        course_key = CourseKey.from_string(course_id)
        student = User.objects.prefetch_related("groups").get(id=student_id)
	course = get_course_with_access(student, 'load', course_key, depth=None, check_if_enrolled=True)

        show_generate_cert_btn = certs_api.cert_generation_enabled(course_key)	
        grade_summary = get_grades(course,student)		
	

	print "grade_summary====================",grade_summary
	
	failed = None
	if grade_summary["totaled_scores"]:
		if grade_summary["percent"]   < course.grading_policy["GRADE_CUTOFFS"]["Pass"]:
			failed = True
	
	
	context = {
                        'passed': grade_summary,
                        'course':course,
			'student':student,
			'failed':failed
                }
       	if grade_summary["percent"]  and grade_summary["percent"]   >= course.grading_policy["GRADE_CUTOFFS"]["Pass"]:
		

		print "in totaled score"
		context.update({
                        'show_generate_cert_btn':True
                })

            	cert_status = certs_api.certificate_downloadable_status(student, course_key)
	    	context.update(cert_status)
        	# showing the certificate web view button if feature flags are enabled.
        	if certs_api.has_html_certificates_enabled(course_key, course):
            		if certs_api.get_active_web_certificate(course) is not None:
              			context.update({
                    			'show_cert_web_view': True,
                    			'cert_web_view_url': certs_api.get_certificate_url(course_id=course_key, uuid=cert_status['uuid']),
					'show_generate_cert_btn':True
                		})
            		else:
                		context.update({
                    			'is_downloadable': False,
                    			'is_generating': True,
                    			'download_url': None
                		})

        print "outside totaled score"
	return context


    # TO-DO: change this to create the scenarios you'd like to see in the
    # workbench while developing your XBlock.
    @staticmethod
    def workbench_scenarios():
        """A canned scenario for display in the workbench."""
        return [
            ("CertRequestXBlock",
             """<cert_request/>
             """),
            ("Multiple CertRequestXBlock",
             """<vertical_demo>
                <cert_request/>
                <cert_request/>
                <cert_request/>
                </vertical_demo>
             """),
        ]

def grade_for_percentage(grade_cutoffs, percentage):
    """
    Returns a letter grade as defined in grading_policy (e.g. 'A' 'B' 'C' for 6.002x) or None.

    Arguments
    - grade_cutoffs is a dictionary mapping a grade to the lowest
        possible percentage to earn that grade.
    - percentage is the final percent across all problems in a course
    """

    letter_grade = None

    # Possible grades, sorted in descending order of score
    descending_grades = sorted(grade_cutoffs, key=lambda x: grade_cutoffs[x], reverse=True)
    for possible_grade in descending_grades:
        if percentage >= grade_cutoffs[possible_grade]:
            letter_grade = possible_grade
            break

    return letter_grade
