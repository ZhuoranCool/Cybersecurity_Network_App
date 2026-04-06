# CS 1653 Project: Phase 1 Feedback

__Group:__ CryptExpert

__Names:__ Chen, Tingxu; Diaz, Gabriela; Gombkoto, Ava J; Mckee, Alexa; Wang, Zhuoran

__Users:__ tic128; gsd23; ajg258; alm577; zhw195

## Comments

### Group information

Great discussion of your breadth of skills and how you will work together. I
appreciated that you referenced specific experiences. I like how you balance
accountability with creating an environment where everyone can feel comfortable
asking questions.

10 / 10

### Design Proposal

I prefer more natural prose, where you describe your proposal and answer the
questions in paragraph form, rather than include the prompts and answer them in
short fragments. Bulleted lists are fine for some things, but future writeups
should look more like papers and less like worksheets. Please let me know if i’m
not being clear about what i mean by this.

Users should have one specific identifier. The Pitt ID and Pitt email seem
redundant in combination (since a Pitt ID is an email when suffixed with
`@pitt.edu`). The name can be used for displaying, but it is not guaranteed to
be a unique identifier and shouldn’t be treated like an ID.

Rather than administering a database server, i recommend looking into
[`sqlite`](https://www.geeksforgeeks.org/sqlite/sqlite-tutorial/).

Sending email programmatically might be a challenging setup, so you might want
to start early on this component and/or think about alternatives for user setup
and login.

Who can delete users? Can they only delete themselves?

I like the idea of having access determined by membership in a course (which
acts as a sort of role).

Certain permissions are only available to instructors. Is this a hard-coded
role? Can an instructor change the membership for ANY course? Is there some
tracking of which instructor “owns” a course? Can any instructor change a
student to a TA? Are they then a TA for all courses? Who gets to decide (or
phrased another way, who is responsible for checking) whether someone is an
instructor? You mention an admin, but don’t describe who that is or what their
(other) responsibilities are. I’m happy to discuss details and alternatives on
Discord or in office hours as you continue to refine your access model.

Consider how you’ll store the (many-to-many) course membership relation, both
during execution and on disk when shut down.

I can’t tell if you intend for only instructors to create documents.

The inclusion of “grades” comes somewhat out of nowhere—is this a specific type
of document? Is this an attribute that a document is tagged with, and if so, is
there flexibility in creating other such attributes?

Overall, lots of thought was put into the design, but i think you have some
things left to decide as a group.

45 / 45

### Security Properties

From the description:

> For each property, come up with (i) a name for the property, (ii) a definition
> of what this property entails, (iii) a short description of why this property
> is important, and (iv) any assumptions upon which this property depends.

Your properties lack (ii), (iii), and (iv), which encompasses the bulk of the
details that were assigned. I can predict some based on their names, and many of
the properties are thoughtful, but please read the assigned tasks more carefully
in future phases.

These don’t feel like security properties (but it’s a little hard to tell
without details): Data minimization, Failure behavior predictability

30 / 45

## Overall

What type of user interface will you be developing, and how will it be used?

Very thoughtful group arrangements and a great starting point for your design.
Some details require some more thought, which you’ll have the opportunity to
engage with in Phase 2.

85 / 100

