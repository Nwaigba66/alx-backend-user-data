#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database

        Args:
            email (str): User's email
            hashed_password (str): User's hashed password

        Returns:
            User: Newly added User object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user in the database based on the given criteria

        Args:
            **kwargs: Arbitrary keyword arguments for filtering

        Returns:
            User: First user found based on the provided criteria

        Raises:
            NoResultFound: If no result is found
            InvalidRequestError: If an invalid query argument is passed
        """
        invalid_args = set(kwargs) - set(User.__table__.columns.keys())
        if invalid_args:
            raise InvalidRequestError
        user = self._session.query(User).filter_by(**kwargs).first()
        if not user:
            raise NoResultFound
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update user attributes in the database

        Args:
            user_id (int): ID of the user to update
            **kwargs: Arbitrary keyword arguments for updating user attributes

        Raises:
            ValueError: If an invalid argument is passed
        """
        user = self.find_user_by(id=user_id)

        # Check for invalid arguments
        invalid_args = set(kwargs) - set(User.__table__.columns.keys())
        if invalid_args:
            raise ValueError

        # Update user attributes
        for key, value in kwargs.items():
            setattr(user, key, value)

        # Commit changes to the database
        self._session.commit()
