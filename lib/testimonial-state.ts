/** Result of the testimonial server action in app/actions/testimonials.ts. */
export interface TestimonialActionState {
  status: 'idle' | 'success' | 'error';
  message: string;
}

export const initialTestimonialState: TestimonialActionState = { status: 'idle', message: '' };

/** A quote as shown on the landing page. */
export interface PublicTestimonial {
  quote: string;
  displayName: string;
  role: string | null;
}
